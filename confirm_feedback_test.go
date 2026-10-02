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
	ok, reason := cfg.confirmHMAC(context.Background())
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
