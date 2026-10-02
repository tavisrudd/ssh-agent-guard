package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnrollmentInstructionsHonorConfig(t *testing.T) {
	cfg := DefaultConfirmConfig()
	cfg.ResponseDir = "/tmp/user's state/confirm"
	cfg.Challenge = "custom challenge"
	cfg.Slot = "1"
	var out bytes.Buffer
	enrollmentInstructions(&out, cfg, "11583827")
	for _, want := range []string{"ykchalresp '-1' 'custom challenge'", "11583827.response", "umask 077; set -C", "user'\\''s", "no daemon restart"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("instructions missing %q: %s", want, out.String())
		}
	}
}

func TestShellQuoteRoundTrip(t *testing.T) {
	for _, value := range []string{"user's state", "$(false); `false`", "line\nbreak", ""} {
		out, err := exec.Command("bash", "-c", "printf '%s' "+shellQuote(value)).Output()
		if err != nil || string(out) != value {
			t.Fatalf("quote %q: got %q, err %v", value, out, err)
		}
	}
}

func TestEnrollmentCommandsCreatePrivateFileAndRefuseOverwrite(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "ykchalresp")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf '%s\\n' 0123456789012345678901234567890123456789\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfirmConfig()
	cfg.ResponseDir = filepath.Join(dir, "user's state")
	var out bytes.Buffer
	enrollmentInstructions(&out, cfg, "11583827")
	var lines []string
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(line, "  ") {
			lines = append(lines, line)
		}
	}
	script := strings.Join(lines, "\n")
	run := func() error {
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
		return cmd.Run()
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.ResponseDir, "11583827.response")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode %v", info.Mode())
	}
	if err := run(); err == nil {
		t.Fatal("enrollment overwrote existing response")
	}
}
