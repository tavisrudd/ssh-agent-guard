package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// ConfirmPIN writes a pending confirmation request and waits for a response.
// The user is notified via tmux status bar (by the caller's SetConfirming) and
// activates the confirm prompt with a tmux keybinding which runs ssh-ag-confirm.
func (c *ConfirmConfig) ConfirmPIN(parent context.Context, caller *CallerContext, session *SessionBindInfo, key ssh.PublicKey) bool {
	// Create pending directory
	if err := os.MkdirAll(c.PendingDir, 0700); err != nil {
		log.Printf("confirm_pin: mkdir %s: %v", c.PendingDir, err)
		return false
	}

	// Generate request ID and nonce for response authentication.
	// The nonce prevents a same-user attacker from blindly writing "allow"
	// to the FIFO — they must read the nonce from the request file first.
	reqID := fmt.Sprintf("%d-%d", time.Now().UnixNano(), caller.PID)
	nonce := generateNonce()

	// Write request details for the helper to display
	reqPath := filepath.Join(c.PendingDir, reqID+".yaml")
	if err := c.writeRequest(reqPath, caller, session, key, nonce); err != nil {
		log.Printf("confirm_pin: write request: %v", err)
		return false
	}
	defer os.Remove(reqPath)

	// Create FIFO for the helper to write the result
	fifoPath := filepath.Join(c.PendingDir, reqID+".result")
	if err := unix.Mkfifo(fifoPath, 0600); err != nil {
		log.Printf("confirm_pin: mkfifo %s: %v", fifoPath, err)
		return false
	}
	defer os.Remove(fifoPath)

	dest := SignDest(caller, session)
	log.Printf("confirm_pin: pending %s → %s (req=%s)", caller.Name, dest, reqID)

	// Wait for the user to respond via ssh-ag-confirm keybinding
	// Cancelled if client disconnects, timeout expires, or deny file touched
	ctx, cancel := context.WithTimeout(parent, c.PINTimeout)
	defer cancel()

	startTime := time.Now()

	fifoCh := make(chan string, 1)
	go func() {
		fifoCh <- c.readFIFO(ctx, fifoPath)
	}()

	denyCh := c.watchDenyFile(ctx, startTime)

	var result string
	select {
	case result = <-fifoCh:
	case <-denyCh:
		cancel()
		log.Printf("confirm_pin: explicitly denied via deny file for %s → %s", caller.Name, dest)
		return false
	}

	// Response must be "allow <nonce>" to prevent blind FIFO injection.
	// A same-user attacker monitoring the pending directory could write to the
	// FIFO, but they must read the nonce from the 0600 request file first.
	if result == "allow "+nonce {
		log.Printf("confirm_pin: approved for %s → %s", caller.Name, dest)
		return true
	}

	// Accept bare "allow" with a warning for backwards compatibility during
	// transition. TODO: remove after one release cycle.
	if result == "allow" {
		log.Printf("confirm_pin: approved for %s → %s (WARN: nonce missing — update ssh-ag-confirm)", caller.Name, dest)
		return true
	}

	log.Printf("confirm_pin: denied for %s → %s (result=%q)", caller.Name, dest, result)
	return false
}

// writeRequest writes the confirm request details as YAML for the helper.
// The nonce is included so the helper can echo it back in the FIFO response,
// proving it read the request file (which is 0600, user-only).
func (c *ConfirmConfig) writeRequest(path string, caller *CallerContext, session *SessionBindInfo, key ssh.PublicKey, nonce string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	dest := SignDest(caller, session)
	fingerprint := ssh.FingerprintSHA256(key)

	fmt.Fprintf(f, "caller: %s\n", caller.Name)
	fmt.Fprintf(f, "pid: %d\n", caller.PID)
	fmt.Fprintf(f, "dest: %s\n", dest)
	fmt.Fprintf(f, "key: %s\n", fingerprint)
	fmt.Fprintf(f, "nonce: %s\n", nonce)
	if caller.TmuxWindow != "" {
		fmt.Fprintf(f, "tmux_window: %s\n", caller.TmuxWindow)
	}
	if caller.CWD != "" {
		fmt.Fprintf(f, "cwd: %s\n", caller.CWD)
	}
	return nil
}

// generateNonce returns a 16-byte hex-encoded random string for FIFO
// response authentication.
func generateNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand should never fail on Linux (/dev/urandom).
		// Fall back to timestamp-based nonce rather than failing the confirm.
		log.Printf("confirm_pin: crypto/rand failed: %v (using fallback)", err)
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// readFIFO reads a single line from a FIFO, respecting context cancellation.
// Returns the trimmed line or "" on timeout/error.
//
// Known limitation: on context cancel, the inner goroutine blocked in os.Open
// (FIFO open blocks until a writer connects) will leak until the process exits.
// os.Remove on the FIFO path does not reliably unblock a pending open(2) on
// Linux. Fixing this requires O_NONBLOCK + poll/select at syscall level, which
// isn't worth the complexity — cancelled confirms are rare (client disconnect
// during the ~120s confirm window), and the leaked goroutine is just a blocked
// syscall with minimal memory (~2KB stack).
func (c *ConfirmConfig) readFIFO(ctx context.Context, fifoPath string) string {
	type fifoResult struct {
		line string
		err  error
	}
	ch := make(chan fifoResult, 1)

	go func() {
		f, err := os.Open(fifoPath)
		if err != nil {
			ch <- fifoResult{"", err}
			return
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		if scanner.Scan() {
			ch <- fifoResult{strings.TrimSpace(scanner.Text()), nil}
		} else {
			ch <- fifoResult{"", scanner.Err()}
		}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			log.Printf("confirm_pin: fifo read: %v", r.err)
			return ""
		}
		return r.line
	case <-ctx.Done():
		os.Remove(fifoPath)
		log.Printf("confirm_pin: timeout after %s", c.PINTimeout)
		return ""
	}
}
