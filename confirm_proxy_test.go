package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"
	"gopkg.in/yaml.v3"
)

// guardEnv runs the proxy as main does (handleConnection) in front of an
// in-memory agent, with a confirm-everything policy, the touch path
// (display seam) and fake YubiKey binaries.
type guardEnv struct {
	dir, proxy, stateDir string
	logger               *Logger
	cfg                  ConfirmConfig
}

func newGuardEnv(t *testing.T, ykchalresp string) *guardEnv {
	t.Helper()
	dir := t.TempDir()
	policy := newTestPolicy(t, "default_action: confirm\nrules: []\n")
	info := filepath.Join(dir, "ykinfo")
	chal := filepath.Join(dir, "ykchalresp")
	os.WriteFile(info, []byte("#!/bin/sh\necho 'serial: 11583827'\n"), 0700)
	os.WriteFile(chal, []byte("#!/bin/sh\n"+ykchalresp), 0700)
	os.WriteFile(filepath.Join(dir, "11583827.response"), []byte("expected\n"), 0600)
	old := resolvedBinsVal.Load()
	resolvedBinsVal.Store(&resolvedBins{ykinfo: info, ykchalresp: chal})
	oldDisplay := hasActiveDisplayFn
	hasActiveDisplayFn = func() bool { return true }
	pendingConfirms.Store(0)
	t.Cleanup(func() {
		resolvedBinsVal.Store(old)
		hasActiveDisplayFn = oldDisplay
		pendingConfirms.Store(0)
	})

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyring := agent.NewKeyring()
	keyring.Add(agent.AddedKey{PrivateKey: priv})
	up := filepath.Join(dir, "up.sock")
	ul, err := net.Listen("unix", up)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ul.Close() })
	go func() {
		for {
			c, err := ul.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(keyring, c)
		}
	}()

	e := &guardEnv{dir: dir, proxy: filepath.Join(dir, "p.sock"), stateDir: filepath.Join(dir, "state")}
	e.logger = NewLogger(e.stateDir, policy)
	e.cfg = DefaultConfirmConfig()
	e.cfg.ResponseDir = dir
	e.cfg.DenyPath = filepath.Join(dir, "deny")
	e.cfg.PendingDir = filepath.Join(dir, "pending")
	pl, err := net.Listen("unix", e.proxy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pl.Close() })
	go func() {
		for {
			c, err := pl.Accept()
			if err != nil {
				return
			}
			go handleConnection(c, up, e.logger, nil, policy, &e.cfg)
		}
	}()
	return e
}

func (e *guardEnv) sign(t *testing.T) (net.Conn, func() error) {
	t.Helper()
	conn, err := net.Dial("unix", e.proxy)
	if err != nil {
		t.Fatal(err)
	}
	client := agent.NewClient(conn)
	keys, err := client.List()
	if err != nil {
		t.Fatal(err)
	}
	return conn, func() error {
		_, err := client.Sign(keys[0], []byte("test"))
		return err
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (e *guardEnv) waiting() int {
	e.logger.mu.Lock()
	defer e.logger.mu.Unlock()
	return e.logger.waiting
}

// Through the real proxy wiring: while the key works for a request the bar
// is confirming with a single pending request, every request is approved,
// and the waiting count returns to zero.
func TestProxyTouchShowsHolder(t *testing.T) {
	seen := filepath.Join(t.TempDir(), "seen")
	os.Mkdir(seen, 0700)
	e := newGuardEnv(t, "cp STATE/current.yaml "+seen+"/$$\nsleep 0.05\necho expected\n")
	// The fake reads the bar the guard wrote.
	chal := filepath.Join(e.dir, "ykchalresp")
	data, _ := os.ReadFile(chal)
	os.WriteFile(chal, []byte(strings.ReplaceAll(string(data), "STATE", e.stateDir)), 0700)

	const n = 4
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		conn, sign := e.sign(t)
		defer conn.Close()
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- sign()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("sign failed: %v", err)
		}
	}
	entries, _ := os.ReadDir(seen)
	if len(entries) != n {
		t.Fatalf("key used %d times, want %d", len(entries), n)
	}
	for _, en := range entries {
		var st currentStatus
		data, _ := os.ReadFile(filepath.Join(seen, en.Name()))
		yaml.Unmarshal(data, &st)
		if st.State != "confirming" || st.Pending == nil || !strings.HasPrefix(st.Text, "TOUCH YK:") {
			t.Errorf("key in use while the bar showed %q %q", st.State, st.Text)
		}
	}
	if w := e.waiting(); w != 0 {
		t.Errorf("waiting count = %d after all requests, want 0", w)
	}
}

// A client that disconnects while waiting for the key leaves the queue at
// once: pending and waiting counts return to zero.
func TestProxyDisconnectLeavesQueue(t *testing.T) {
	e := newGuardEnv(t, "echo expected\n")
	release, err := acquireYubiKey(context.Background(), nil) // another request holds the key
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	conn, sign := e.sign(t)
	go sign()
	waitFor(t, "the request to queue", func() bool { return pendingConfirms.Load() == 1 && e.waiting() == 1 })
	st := readCurrent(t, e.stateDir)
	if st.State == "confirming" || !strings.Contains(st.Text, "1 waiting for YubiKey") {
		t.Errorf("a queued request should only be counted: %q %q", st.State, st.Text)
	}
	conn.Close()
	waitFor(t, "the queue to empty", func() bool { return pendingConfirms.Load() == 0 && e.waiting() == 0 })
}

// An idle connection runs no hangup watcher: watchers exist only while a
// request is confirming.
func TestNoWatcherOnIdleConnections(t *testing.T) {
	e := newGuardEnv(t, "echo expected\n")
	var conns []net.Conn
	for i := 0; i < 20; i++ {
		conn, _ := e.sign(t) // List only, no sign
		conns = append(conns, conn)
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	if n := watchersRunning.Load(); n != 0 {
		t.Fatalf("%d hangup watchers for idle connections", n)
	}
}
