package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"

	"golang.org/x/crypto/ssh/agent"
	"gopkg.in/yaml.v3"
)

var verbose bool

func main() {
	var (
		listenPath   string
		upstreamPath string
		stateDir     string
		policyPath   string
		check        bool
		checkPID     int
		checkKey     string
	)

	flag.StringVar(&listenPath, "listen", defaultListenPath(), "proxy socket path")
	flag.StringVar(&upstreamPath, "upstream", defaultUpstreamPath(), "upstream agent socket path")
	flag.StringVar(&stateDir, "state-dir", defaultStateDir(), "state directory for logs")
	flag.StringVar(&policyPath, "policy", defaultPolicyPath(), "policy config path")
	flag.BoolVar(&verbose, "verbose", false, "log all operations including list requests")
	flag.BoolVar(&check, "check", false, "gather caller state and evaluate policy (debug mode)")
	flag.IntVar(&checkPID, "pid", 0, "PID to inspect (default: parent process, --check only)")
	flag.StringVar(&checkKey, "key", "", "key fingerprint for policy evaluation (--check only)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: ssh-agent-guard [--flags]\n\n")
		fmt.Fprintf(os.Stderr, "Daemon mode (default):\n")
		fmt.Fprintf(os.Stderr, "  --listen PATH      proxy socket path\n")
		fmt.Fprintf(os.Stderr, "  --upstream PATH    upstream agent socket path\n")
		fmt.Fprintf(os.Stderr, "  --state-dir PATH   state directory for logs\n")
		fmt.Fprintf(os.Stderr, "  --policy PATH      policy config path\n")
		fmt.Fprintf(os.Stderr, "  --verbose          log all operations\n")
		fmt.Fprintf(os.Stderr, "\nCheck mode:\n")
		fmt.Fprintf(os.Stderr, "  --check            gather caller state and evaluate policy\n")
		fmt.Fprintf(os.Stderr, "  --pid PID          PID to inspect (default: parent process)\n")
		fmt.Fprintf(os.Stderr, "  --key FINGERPRINT  key fingerprint for policy matching\n")
	}

	flag.Parse()

	if check {
		runCheck(policyPath, checkPID, checkKey)
		return
	}

	errorFile := filepath.Join(stateDir, "config_error.yaml")
	policy, initialResult := NewPolicy(policyPath)

	// Build confirm config from policy and write pin.env for the helper script
	var confirmCfg atomic.Pointer[ConfirmConfig]
	updateConfirmCfg := func() {
		cfg := policy.ConfirmConfig()
		// Override directory paths from --state-dir flag
		cfg.ResponseDir = filepath.Join(stateDir, "confirm")
		cfg.PendingDir = filepath.Join(stateDir, "pending")
		cfg.DenyPath = filepath.Join(stateDir, "confirm", "denied")
		confirmCfg.Store(&cfg)
		writePINEnv(filepath.Join(stateDir, "confirm", "pin.env"), &cfg)
	}

	logger := NewLogger(stateDir, policy)
	logger.LogConfigChange(initialResult)
	syncErrorFile(errorFile, initialResult)

	policy.OnReload(func(result LoadResult) {
		updateConfirmCfg()
		logger.LogConfigChange(result)
		logger.NotifyReload()
		syncErrorFile(errorFile, result)
	})
	policy.Watch()
	updateConfirmCfg()

	// Compile ControlPath regex for mux forwarded_via extraction
	initMuxViaRegex()

	// Load known_hosts for reverse host key → hostname lookup
	knownHostsPath := filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts")
	var knownHosts atomic.Pointer[KnownHostsResolver]
	knownHosts.Store(NewKnownHostsResolver(knownHostsPath))

	// Remove stale socket from previous run
	os.Remove(listenPath)

	// Set restrictive umask before Listen so the socket is created with 0600
	// from the start, closing the chmod-after-listen race window.
	oldUmask := syscall.Umask(0077)

	listener, err := net.Listen("unix", listenPath)
	if err != nil {
		syscall.Umask(oldUmask)
		log.Fatalf("listen %s: %v", listenPath, err)
	}

	syscall.Umask(oldUmask)
	defer listener.Close()
	defer os.Remove(listenPath)

	log.Printf("ssh-agent-guard pid=%d listen=%s upstream=%s state=%s",
		os.Getpid(), listenPath, upstreamPath, stateDir)

	// SIGHUP reloads policy + known_hosts
	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	go func() {
		for range hupCh {
			log.Printf("SIGHUP: reloading policy and known_hosts")
			result := policy.Load()
			knownHosts.Store(NewKnownHostsResolver(knownHostsPath))
			updateConfirmCfg()
			logger.LogConfigChange(result)
			logger.NotifyReload()
			syncErrorFile(errorFile, result)
		}
	}()

	// Shut down cleanly on signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("received %v, shutting down", sig)
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed") {
				break
			}
			log.Printf("accept: %v", err)
			continue
		}
		go handleConnection(conn, upstreamPath, logger, knownHosts.Load(), policy, confirmCfg.Load())
	}
}

func handleConnection(clientConn net.Conn, upstreamPath string, logger *Logger, knownHosts *KnownHostsResolver, policy *Policy, confirmCfg *ConfirmConfig) {
	defer clientConn.Close()

	// Identify the connecting process via SO_PEERCRED before anything else
	// (the process may exit soon after connecting)
	caller := getCallerContext(clientConn)

	if caller.IsContainer {
		log.Printf("connect: %s (pid %d) from container (ns mismatches: %v) — caller identity may be incomplete",
			caller.Name, caller.PID, caller.NamespaceMismatches)
	} else if verbose {
		log.Printf("connect: %s (pid %d) from %s", caller.Name, caller.PID, caller.CWD)
	}

	// Open a dedicated upstream connection for this client
	upstreamConn, err := net.Dial("unix", upstreamPath)
	if err != nil {
		log.Printf("upstream dial %s: %v", upstreamPath, err)
		return
	}
	defer upstreamConn.Close()

	// Context cancelled when this connection handler returns (client disconnect)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	upstream := agent.NewClient(upstreamConn)
	proxy := &ProxyAgent{
		upstream:   upstream,
		caller:     caller,
		logger:     logger,
		knownHosts: knownHosts,
		policy:     policy,
		confirmCfg: confirmCfg,
		ctx:        ctx,
	}

	if err := agent.ServeAgent(proxy, clientConn); err != nil {
		if err != io.EOF {
			log.Printf("serve pid=%d: %v", caller.PID, err)
		}
	}
}

func defaultListenPath() string {
	return filepath.Join(xdgRuntimeDir(), "ssh-agent-guard.sock")
}

func defaultUpstreamPath() string {
	return filepath.Join(xdgRuntimeDir(), "gnupg", "S.gpg-agent.ssh")
}

func defaultStateDir() string {
	return filepath.Join(os.Getenv("HOME"), ".local", "state", "ssh-ag")
}

func xdgRuntimeDir() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return dir
	}
	return fmt.Sprintf("/run/user/%d", os.Getuid())
}

// syncErrorFile writes or removes the config error file based on the load result.
func syncErrorFile(path string, result LoadResult) {
	if result.OK {
		os.Remove(path)
	} else {
		type errorFile struct {
			Errors []string `yaml:"errors"`
		}
		data, err := yaml.Marshal(&errorFile{Errors: result.Errors})
		if err != nil {
			log.Printf("syncErrorFile: marshal: %v", err)
			return
		}
		os.WriteFile(path, data, 0600)
	}
}

// writePINEnv writes a shell-sourceable config file for the ssh-ag-confirm
// script so it can read the configured PIN slot from the policy.
func writePINEnv(path string, cfg *ConfirmConfig) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		log.Printf("writePINEnv: mkdir: %v", err)
		return
	}
	content := fmt.Sprintf("# Generated by ssh-agent-guard from policy confirm.pin section\nPIN_SLOT=%s\n", cfg.PINSlot)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		log.Printf("writePINEnv: write %s: %v", path, err)
	}
}
