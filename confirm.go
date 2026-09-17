package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
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

	// Rate limiting: max concurrent pending confirmations (0 = unlimited)
	MaxPending int
}

func DefaultConfirmConfig() ConfirmConfig {
	return ConfirmConfig{
		Challenge:  "deadbeef",
		Slot:       "2",
		Timeout:    20 * time.Second,
		PINSlot:    "1",
		PINTimeout: 120 * time.Second,
		MaxPending: 3,
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
		if paths, ok := v.([]string); ok {
			return paths
		}
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
var procPIDRe = regexp.MustCompile(`^[0-9]+$`)

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
		if subtle.ConstantTimeCompare([]byte(r.response), []byte(expected)) == 1 {
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

// VerifyPIN performs PIN challenge-response inside the daemon. The helper is
// deliberately not trusted to return an allow/deny verdict.
func (c *ConfirmConfig) VerifyPIN(ctx context.Context, pin []byte) bool {
	expectedBytes, err := os.ReadFile(filepath.Join(c.ResponseDir, "slot"+c.PINSlot+".response"))
	if err != nil {
		log.Printf("confirm_pin: expected response: %v", err)
		return false
	}
	expected := strings.TrimSpace(string(expectedBytes))
	if expected == "" {
		return false
	}

	cmd := exec.CommandContext(ctx, getResolvedBins().ykchalresp, "-"+c.PINSlot, "-i-")
	cmd.Stdin = bytes.NewReader(pin)
	out, err := cmd.Output()
	if err != nil {
		log.Printf("confirm_pin: ykchalresp failed: %v", err)
		return false
	}
	response := strings.TrimSpace(string(out))
	return subtle.ConstantTimeCompare([]byte(response), []byte(expected)) == 1
}

type swaySocketProbe func(context.Context, string, string) error

func probeSwaySocket(ctx context.Context, swaymsgBin, socket string) error {
	return exec.CommandContext(ctx, swaymsgBin, "-s", socket, "-t", "get_version").Run()
}

// swaySocketCandidates returns the inherited socket first when present, then
// runtime-directory sockets newest-first.  Sway does not remove its IPC socket
// after every abnormal exit, so lexical order is not a useful freshness signal.
func swaySocketCandidates(inherited string) []string {
	matches, _ := filepath.Glob(filepath.Join(xdgRuntimeDir(), "sway-ipc.*.sock"))
	sort.SliceStable(matches, func(i, j int) bool {
		iInfo, iErr := os.Stat(matches[i])
		jInfo, jErr := os.Stat(matches[j])
		if iErr != nil {
			return false
		}
		if jErr != nil {
			return true
		}
		return iInfo.ModTime().After(jInfo.ModTime())
	})

	seen := make(map[string]bool, len(matches)+1)
	candidates := make([]string, 0, len(matches)+1)
	for _, socket := range append([]string{inherited}, matches...) {
		if socket != "" && !seen[socket] {
			seen[socket] = true
			candidates = append(candidates, socket)
		}
	}
	return candidates
}

func findActiveSwaySocket(ctx context.Context, swaymsgBin string) (string, error) {
	return findActiveSwaySocketFrom(ctx, swaymsgBin,
		swaySocketCandidates(os.Getenv("SWAYSOCK")), probeSwaySocket)
}

func findActiveSwaySocketFrom(ctx context.Context, swaymsgBin string, candidates []string, probe swaySocketProbe) (string, error) {
	for _, socket := range candidates {
		if err := probe(ctx, swaymsgBin, socket); err == nil {
			return socket, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return "", fmt.Errorf("no reachable Sway IPC socket")
}

// swaylockIsActive uses the same readiness invariant as the lock launcher:
// swaylock-active is written only after the session-lock protocol is acquired,
// and lock.sh holds lock.sh.lock until swaylock exits.  This avoids depending
// on process names, which Nix changes to .swaylock-wrapped.
func swaylockIsActive() bool {
	runtimeDir := xdgRuntimeDir()
	markerInfo, err := os.Stat(filepath.Join(runtimeDir, "swaylock-active"))
	if err == nil && markerInfo.Size() > 0 {
		lockFile, openErr := os.OpenFile(filepath.Join(runtimeDir, "lock.sh.lock"), os.O_RDWR, 0)
		if openErr != nil {
			// A ready marker without a readable lock file is inconsistent.  Fail
			// closed rather than presenting a GUI confirmation over the lockscreen.
			return true
		}
		defer lockFile.Close()

		flockErr := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if flockErr != nil {
			return true
		}
		_ = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
	}

	// Support installations that launch swaylock directly rather than through
	// lock.sh.  Inspect executable names instead of /proc/PID/comm, which is
	// truncated and differs for Nix-wrapped programs.
	procEntries, _ := os.ReadDir("/proc")
	for _, entry := range procEntries {
		if !entry.IsDir() || !procPIDRe.MatchString(entry.Name()) {
			continue
		}
		procDir := filepath.Join("/proc", entry.Name())
		info, statErr := os.Stat(procDir)
		if statErr != nil {
			continue
		}
		stat, ok := info.Sys().(*unix.Stat_t)
		if !ok || stat.Uid != uint32(os.Getuid()) {
			continue
		}
		exe, readErr := os.Readlink(filepath.Join(procDir, "exe"))
		if readErr == nil && isSwaylockExecutable(exe) {
			return true
		}
	}
	return false
}

func isSwaylockExecutable(exe string) bool {
	base := strings.TrimSuffix(filepath.Base(exe), " (deleted)")
	return base == "swaylock" || base == ".swaylock-wrapped"
}

type swayOutput struct {
	Name   string `json:"name"`
	Active bool   `json:"active"`
	Power  *bool  `json:"power"`
}

func hasUsableSwayOutput(data []byte, excludedNames string) (bool, error) {
	var outputs []swayOutput
	if err := json.Unmarshal(data, &outputs); err != nil {
		return false, err
	}

	excluded := make(map[string]struct{})
	for _, name := range strings.Split(excludedNames, ",") {
		if name = strings.TrimSpace(name); name != "" {
			excluded[name] = struct{}{}
		}
	}

	for _, output := range outputs {
		if !output.Active || (output.Power != nil && !*output.Power) {
			continue
		}
		if _, skip := excluded[output.Name]; !skip {
			return true, nil
		}
	}
	return false, nil
}

// hasActiveDisplay checks whether the local sway session has a usable display.
// Returns false if swaylock is active, no active outputs, or no Sway IPC socket
// is reachable.
// Mirrors avoid_gui() logic in pinentry-auto.
func hasActiveDisplay() bool {
	swaymsgBin := findBin("swaymsg")

	// Probe the inherited socket first, then discover a live replacement.  The
	// daemon's environment is immutable, while Sway's socket changes whenever
	// the compositor is fully restarted.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	swaySocket, err := findActiveSwaySocket(ctx, swaymsgBin)
	if err != nil {
		log.Printf("hasActiveDisplay: swaymsg not reachable: %v", err)
		return false
	}

	// Swaylock active — GUI prompts are hidden behind the lockscreen.
	if swaylockIsActive() {
		log.Printf("hasActiveDisplay: swaylock running")
		return false
	}

	// Check for active outputs.
	// EXCLUDE_OUTPUTS env var can list output names to ignore (comma-separated),
	// e.g. built-in LCDs that don't indicate user presence.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	cmd := exec.CommandContext(ctx2, swaymsgBin, "-s", swaySocket, "-t", "get_outputs", "-r")
	out, err := cmd.Output()
	if err != nil {
		log.Printf("hasActiveDisplay: get_outputs failed: %v", err)
		return false
	}
	active, err := hasUsableSwayOutput(out, os.Getenv("SSH_AG_EXCLUDE_OUTPUTS"))
	if err != nil {
		log.Printf("hasActiveDisplay: invalid get_outputs response: %v", err)
		return false
	}
	if !active {
		log.Printf("hasActiveDisplay: no active outputs")
		return false
	}

	return true
}
