package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMissingEnrollmentFeedback(t *testing.T) {
	dir := t.TempDir()
	info := filepath.Join(dir, "ykinfo")
	if err := os.WriteFile(info, []byte("#!/bin/sh\necho 'serial: 11583827'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	old := resolvedBinsVal.Load()
	resolvedBinsVal.Store(&resolvedBins{ykinfo: info, ykchalresp: filepath.Join(dir, "must-not-run")})
	t.Cleanup(func() { resolvedBinsVal.Store(old) })
	cfg := DefaultConfirmConfig()
	cfg.ResponseDir = dir
	ok, reason := cfg.confirmHMAC(context.Background(), nil)
	if ok {
		t.Fatal("unenrolled key was accepted")
	}
	for _, want := range []string{"11583827 is not enrolled", "slot 2", "deadbeef", filepath.Join(dir, "11583827.response")} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason %q missing %q", reason, want)
		}
	}
}

func TestConfirmationFailureReachesStatusAndEvent(t *testing.T) {
	keyring := agent.NewKeyring()
	private, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Add(agent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	keys, err := keyring.List()
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.ParsePublicKey(keys[0].Blob)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logger := NewLogger(dir, nil)
	logger.renderBin = "/bin/true"
	denied := false
	reason := "YubiKey 11583827 is not enrolled; run ssh-agent-guard doctor for enrollment instructions"
	logger.LogSign(&CallerContext{Name: "ssh", SSHDest: "nano"}, key, nil, EvalResult{Action: Deny, Confirmed: &denied, ConfirmMethod: "touch", ConfirmError: reason}, nil)
	data, err := os.ReadFile(filepath.Join(dir, "current.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var status currentStatus
	if err := yaml.Unmarshal(data, &status); err != nil {
		t.Fatal(err)
	}
	if status.Previous == nil || status.Previous.ConfirmError != reason {
		t.Fatalf("failure missing from status: %s", data)
	}
	if !strings.Contains(status.Text, "11583827 is not enrolled (run ssh-agent-guard doctor)") {
		t.Fatalf("unhelpful status: %q", status.Text)
	}
	data, err = os.ReadFile(status.Previous.LogFile)
	if err != nil {
		t.Fatal(err)
	}
	var event logEvent
	if err := yaml.Unmarshal(data, &event); err != nil {
		t.Fatal(err)
	}
	if event.ConfirmError != reason {
		t.Fatalf("failure missing from event: %s", data)
	}
}

// Parallel sign requests take the YubiKey one at a time: the fake ykinfo
// and ykchalresp fail when another holds the "device", as the real key
// does, so every request succeeds only if access is serialized.
func TestConcurrentConfirmationsShareYubiKey(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "device")
	busy := "mkdir " + lock + " 2>/dev/null || exit 1\ntrap 'rmdir " + lock + "' EXIT\n"
	info := filepath.Join(dir, "ykinfo")
	chal := filepath.Join(dir, "ykchalresp")
	if err := os.WriteFile(info, []byte("#!/bin/sh\n"+busy+"sleep 0.05\necho 'serial: 11583827'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(chal, []byte("#!/bin/sh\n"+busy+"sleep 0.1\necho expected\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "11583827.response"), []byte("expected\n"), 0600); err != nil {
		t.Fatal(err)
	}
	old := resolvedBinsVal.Load()
	resolvedBinsVal.Store(&resolvedBins{ykinfo: info, ykchalresp: chal})
	t.Cleanup(func() { resolvedBinsVal.Store(old) })
	cfg := DefaultConfirmConfig()
	cfg.ResponseDir = dir
	cfg.DenyPath = filepath.Join(dir, "deny")

	const n = 5
	type res struct {
		ok     bool
		reason string
	}
	results := make(chan res, n)
	for i := 0; i < n; i++ {
		go func() {
			ok, reason := cfg.confirmHMAC(context.Background(), nil)
			results <- res{ok, reason}
		}()
	}
	for i := 0; i < n; i++ {
		if r := <-results; !r.ok {
			t.Errorf("concurrent confirmation failed: %s", r.reason)
		}
	}
}

// A request waiting for the YubiKey ends when its client disconnects.
func TestYubiKeyWaitCancelled(t *testing.T) {
	release, err := acquireYubiKey(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	cfg := DefaultConfirmConfig()
	cfg.DenyPath = filepath.Join(t.TempDir(), "deny")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	ok, reason := cfg.confirmHMAC(ctx, nil)
	if ok || !strings.Contains(reason, "disconnected") {
		t.Fatalf("got ok=%v reason=%q, want a disconnect while waiting", ok, reason)
	}
}

// Touching the deny file cancels a request still waiting for the YubiKey.
func TestYubiKeyWaitDenied(t *testing.T) {
	release, err := acquireYubiKey(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	cfg := DefaultConfirmConfig()
	cfg.DenyPath = filepath.Join(t.TempDir(), "deny")
	go func() {
		time.Sleep(50 * time.Millisecond)
		os.WriteFile(cfg.DenyPath, nil, 0600)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ok, reason := cfg.confirmHMAC(ctx, nil)
	if ok || !strings.Contains(reason, "cancelled") || strings.Contains(reason, "disconnected") {
		t.Fatalf("got ok=%v reason=%q, want an explicit cancel", ok, reason)
	}
}
