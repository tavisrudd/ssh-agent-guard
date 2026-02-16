package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

// ConfirmConfig holds YubiKey confirmation settings.
type ConfirmConfig struct {
	// Touch: local HMAC-SHA1 confirmation (requires physical YubiKey touch)
	Challenge   string        // hex string sent as HMAC challenge
	Slot        string        // YubiKey HMAC slot for touch confirmation
	Timeout     time.Duration // max wait for YubiKey touch
	ResponseDir string        // directory containing {serial}.response files

	// PIN: confirmation via tmux popup (no touch, PIN as challenge)
	PINSlot    string        // YubiKey HMAC slot for PIN confirmation
	PINTimeout time.Duration // max wait for PIN entry
	PendingDir string        // directory for pending confirm requests + FIFOs

	// Explicit deny (touch file to cancel any pending confirm)
	DenyPath string
}

func DefaultConfirmConfig() ConfirmConfig {
	home := os.Getenv("HOME")
	stateDir := filepath.Join(home, ".local", "state", "ssh-ag")
	return ConfirmConfig{
		Challenge:     "deadbeef",
		Slot:          "2",
		Timeout:       20 * time.Second,
		ResponseDir:   filepath.Join(stateDir, "confirm"),
		PINSlot:       "1",
		PINTimeout: 120 * time.Second,
		PendingDir:    filepath.Join(stateDir, "pending"),
		DenyPath:      filepath.Join(stateDir, "confirm", "denied"),
	}
}

// resolvedBins holds paths to required external binaries, resolved and
// validated on each policy load/reload so that path changes take effect
// and missing binaries are detected early.
type resolvedBins struct {
	ykchalresp string
	ykinfo     string
}

var resolvedBinsVal atomic.Pointer[resolvedBins]

// resolveBins resolves required binary paths using the current search paths
// and logs warnings for any that can't be found. Called from Policy.Load().
func resolveBins() {
	bins := &resolvedBins{
		ykchalresp: findBin("ykchalresp"),
		ykinfo:     findBin("ykinfo"),
	}
	for _, entry := range []struct{ name, path string }{
		{"ykchalresp", bins.ykchalresp},
		{"ykinfo", bins.ykinfo},
	} {
		if _, err := os.Stat(entry.path); err != nil {
			log.Printf("policy: %s not found in any search path", entry.name)
		}
	}
	resolvedBinsVal.Store(bins)
}

func getResolvedBins() *resolvedBins {
	if bins := resolvedBinsVal.Load(); bins != nil {
		return bins
	}
	// Before first policy load, resolve on demand
	return &resolvedBins{
		ykchalresp: findBin("ykchalresp"),
		ykinfo:     findBin("ykinfo"),
	}
}

// extraBinPathsVal holds additional directories to search for binaries,
// loaded from the policy file's "path" field. Accessed atomically since
// Policy.Load() writes from the fsnotify/SIGHUP goroutine while findBin()
// reads from connection handler goroutines.
var extraBinPathsVal atomic.Value // stores []string

func getExtraBinPaths() []string {
	if v := extraBinPathsVal.Load(); v != nil {
		return v.([]string)
	}
	return nil
}

// findBin locates a binary by checking policy paths, then system defaults, then PATH.
func findBin(name string) string {
	// Policy-configured paths first
	for _, dir := range getExtraBinPaths() {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	// System defaults
	for _, dir := range []string{
		"/run/current-system/sw/bin",
		"/usr/bin",
		"/usr/local/bin",
	} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	// Fall back to PATH lookup
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return name
}

var serialRe = regexp.MustCompile(`\d+`)

// HasYubiKey checks if a YubiKey is currently connected.
func (c *ConfirmConfig) HasYubiKey() bool {
	return c.getSerial() != ""
}

// ConfirmHMAC performs YubiKey HMAC challenge-response to verify physical presence.
// Returns true if the YubiKey response matches the stored expected value.
// Races ykchalresp against the deny file — touching the deny file cancels immediately.
// The confirming state is already set on the status bar by the caller.
func (c *ConfirmConfig) ConfirmHMAC(parent context.Context) bool {
	// Get YubiKey serial
	serial := c.getSerial()
	if serial == "" {
		log.Printf("confirm: no YubiKey detected")
		return false
	}

	// Load expected response for this serial
	expected := c.loadExpectedResponse(serial)
	if expected == "" {
		log.Printf("confirm: no response file for serial %s", serial)
		return false
	}

	// Run challenge-response with timeout, cancelled if client disconnects
	ctx, cancel := context.WithTimeout(parent, c.Timeout)
	defer cancel()

	// Race: ykchalresp vs deny file
	type hmacResult struct {
		response string
		err      error
	}
	hmacCh := make(chan hmacResult, 1)
	go func() {
		cmd := exec.CommandContext(ctx, getResolvedBins().ykchalresp, "-"+c.Slot, c.Challenge)
		out, err := cmd.Output()
		hmacCh <- hmacResult{strings.TrimSpace(string(out)), err}
	}()

	denyCh := c.watchDenyFile(ctx, time.Now())

	select {
	case r := <-hmacCh:
		if r.err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				log.Printf("confirm: YubiKey timeout after %s", c.Timeout)
			} else {
				log.Printf("confirm: ykchalresp failed: %v", r.err)
			}
			return false
		}
		if r.response == expected {
			log.Printf("confirm: YubiKey response matched (serial %s)", serial)
			return true
		}
		log.Printf("confirm: YubiKey response mismatch (serial %s)", serial)
		return false
	case <-denyCh:
		cancel() // kill ykchalresp
		log.Printf("confirm: explicitly denied via deny file")
		return false
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("confirm: YubiKey timeout after %s", c.Timeout)
		}
		return false
	}
}

// watchDenyFile polls for the deny file, returning a channel that closes when
// the file exists with an mtime at or after startTime. Uses mtime comparison
// instead of existence+removal so that concurrent confirmations all see the
// same deny signal without racing on file creation/deletion.
func (c *ConfirmConfig) watchDenyFile(ctx context.Context, startTime time.Time) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(250 * time.Millisecond):
				if info, err := os.Stat(c.DenyPath); err == nil {
					if !info.ModTime().Before(startTime) {
						close(ch)
						return
					}
				}
			}
		}
	}()
	return ch
}

func (c *ConfirmConfig) getSerial() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, getResolvedBins().ykinfo, "-s")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	m := serialRe.FindString(string(out))
	return m
}

func (c *ConfirmConfig) loadExpectedResponse(serial string) string {
	// Try serial-specific file first, then default
	for _, name := range []string{serial + ".response", "default.response"} {
		path := filepath.Join(c.ResponseDir, name)
		data, err := os.ReadFile(path)
		if err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}

// hasActiveDisplay checks whether the local sway session has a usable display.
// Returns false if swaylock is running, no active outputs, or swaymsg unreachable.
// Mirrors avoid_gui() logic in pinentry-auto.
func hasActiveDisplay() bool {
	swaymsgBin := findBin("swaymsg")

	// Discover SWAYSOCK if not in env (gpg-agent/systemd don't pass it).
	// Build a custom env slice instead of os.Setenv to avoid race with
	// concurrent goroutines. nil swayEnv means "inherit parent env".
	var swayEnv []string
	if os.Getenv("SWAYSOCK") == "" {
		matches, _ := filepath.Glob(fmt.Sprintf("/run/user/%d/sway-ipc.*.sock", os.Getuid()))
		if len(matches) > 0 {
			swayEnv = append(os.Environ(), "SWAYSOCK="+matches[0])
		}
	}

	// Check swaymsg is reachable
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	versionCmd := exec.CommandContext(ctx, swaymsgBin, "-t", "get_version")
	versionCmd.Env = swayEnv
	if err := versionCmd.Run(); err != nil {
		log.Printf("hasActiveDisplay: swaymsg not reachable: %v", err)
		return false
	}

	// Swaylock running — GUI prompts hidden behind lockscreen
	if exec.Command("pgrep", "-x", "swaylock").Run() == nil {
		log.Printf("hasActiveDisplay: swaylock running")
		return false
	}

	// Check for active outputs.
	// EXCLUDE_OUTPUTS env var can list output names to ignore (comma-separated),
	// e.g. built-in LCDs that don't indicate user presence.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	jqBin := findBin("jq")
	cmd := exec.CommandContext(ctx2, swaymsgBin, "-t", "get_outputs", "-r")
	cmd.Env = swayEnv
	out, err := cmd.Output()
	if err != nil {
		log.Printf("hasActiveDisplay: get_outputs failed: %v", err)
		return false
	}
	jqFilter := `[.[] | select(.active)] | length`
	if exclude := os.Getenv("SSH_AG_EXCLUDE_OUTPUTS"); exclude != "" {
		// Build jq filter that excludes named outputs
		parts := strings.Split(exclude, ",")
		var conds []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				conds = append(conds, fmt.Sprintf(`.name != %q`, p))
			}
		}
		if len(conds) > 0 {
			jqFilter = fmt.Sprintf(`[.[] | select(.active and %s)] | length`, strings.Join(conds, " and "))
		}
	}
	jqCmd := exec.Command(jqBin, jqFilter)
	jqCmd.Stdin = strings.NewReader(string(out))
	jqOut, err := jqCmd.Output()
	if err != nil {
		log.Printf("hasActiveDisplay: jq failed: %v", err)
		return false
	}
	count := strings.TrimSpace(string(jqOut))
	if count == "0" {
		log.Printf("hasActiveDisplay: no active outputs")
		return false
	}

	return true
}
