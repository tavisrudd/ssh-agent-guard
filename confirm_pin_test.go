package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestPINResultIsVerifiedByDaemon(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "ykchalresp")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\ncat\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "slot1.response"), []byte("correct-pin\n"), 0600); err != nil {
		t.Fatal(err)
	}
	old := resolvedBinsVal.Load()
	resolvedBinsVal.Store(&resolvedBins{ykchalresp: bin})
	t.Cleanup(func() { resolvedBinsVal.Store(old) })

	cfg := &ConfirmConfig{PINSlot: "1", ResponseDir: dir}
	encoded := base64.StdEncoding.EncodeToString([]byte("correct-pin"))
	pin, ok := parsePINResult("pin nonce "+encoded, "nonce")
	if !ok || !cfg.VerifyPIN(context.Background(), pin) {
		t.Fatal("correct PIN was rejected")
	}
	if _, ok := parsePINResult("pin wrong-nonce "+encoded, "nonce"); ok {
		t.Fatal("wrong nonce was accepted")
	}
	wrong := base64.StdEncoding.EncodeToString([]byte("wrong-pin"))
	pin, ok = parsePINResult("pin nonce "+wrong, "nonce")
	if !ok || cfg.VerifyPIN(context.Background(), pin) {
		t.Fatal("helper-controlled approval bypassed daemon PIN verification")
	}
	if _, ok := parsePINResult("allow nonce", "nonce"); ok {
		t.Fatal("legacy helper allow verdict was trusted")
	}
}

func TestDeniedPINIsNotLogged(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "ykchalresp")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\ncat\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "slot1.response"), []byte("correct-pin\n"), 0600); err != nil {
		t.Fatal(err)
	}
	old := resolvedBinsVal.Load()
	resolvedBinsVal.Store(&resolvedBins{ykchalresp: bin})
	t.Cleanup(func() { resolvedBinsVal.Store(old) })

	var logs bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	secret := "do-not-log-this-pin"
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	cfg := &ConfirmConfig{
		PINSlot:     "1",
		PINTimeout:  5 * time.Second,
		PendingDir:  filepath.Join(dir, "pending"),
		ResponseDir: dir,
		DenyPath:    filepath.Join(dir, "deny"),
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewPublicKey(priv.Public())
	resultCh := make(chan bool, 1)
	go func() {
		resultCh <- cfg.ConfirmPIN(context.Background(), &CallerContext{Name: "ssh", SSHDest: "example.com"}, nil, key)
	}()

	fifoPath := waitForPendingFile(t, cfg.PendingDir, "*.result")
	reqPath := strings.TrimSuffix(fifoPath, ".result") + ".yaml"
	request, err := os.ReadFile(reqPath)
	if err != nil {
		t.Fatal(err)
	}
	var nonce string
	for _, line := range strings.Split(string(request), "\n") {
		if strings.HasPrefix(line, "nonce: ") {
			nonce = strings.TrimPrefix(line, "nonce: ")
		}
	}
	if nonce == "" {
		t.Fatal("confirmation request omitted nonce")
	}
	f, err := os.OpenFile(fifoPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(f, "pin %s %s\n", nonce, encoded); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if <-resultCh {
		t.Fatal("incorrect PIN was approved")
	}
	if strings.Contains(logs.String(), secret) || strings.Contains(logs.String(), encoded) {
		t.Fatal("denied PIN was written to logs")
	}
}

func waitForPendingFile(t *testing.T, dir, pattern string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) == 1 {
			return matches[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for pending confirmation")
	return ""
}

func TestExplicitDenyCancelsPINVerification(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "ykchalresp")
	started := filepath.Join(dir, "started")
	script := fmt.Sprintf("#!/bin/sh\ntouch %q\nwhile :; do :; done\n", started)
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "slot1.response"), []byte("correct\n"), 0600); err != nil {
		t.Fatal(err)
	}
	old := resolvedBinsVal.Load()
	resolvedBinsVal.Store(&resolvedBins{ykchalresp: bin})
	t.Cleanup(func() { resolvedBinsVal.Store(old) })

	cfg := &ConfirmConfig{PINSlot: "1", ResponseDir: dir}
	denyCh := make(chan struct{})
	resultCh := make(chan bool, 1)
	start := time.Now()
	go func() { resultCh <- cfg.verifyPIN(context.Background(), []byte("pin"), denyCh) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("PIN backend did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(denyCh)
	if <-resultCh {
		t.Fatal("explicitly denied PIN verification succeeded")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("explicit deny did not cancel backend promptly: %s", elapsed)
	}
}
