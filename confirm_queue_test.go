package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

func testKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func readCurrent(t *testing.T, stateDir string) currentStatus {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(stateDir, "current.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var st currentStatus
	if err := yaml.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

// The bar shows only the request holding the confirmation; waiting
// requests add a count, and other results do not replace the holder.
func TestStatusShowsOnlyTheHolder(t *testing.T) {
	stateDir := t.TempDir()
	l := NewLogger(stateDir, nil)
	key := testKey(t)
	touch := EvalResult{Action: Confirm, ConfirmMethod: "touch"}

	l.AddWaiting(1) // B waits
	id := l.SetConfirming(&CallerContext{Name: "holder-a"}, key, nil, touch)
	st := readCurrent(t, stateDir)
	if st.State != "confirming" || !strings.Contains(st.Text, "holder-a") || !strings.Contains(st.Text, "+1 waiting") {
		t.Fatalf("holder not shown with waiting count: %+v", st)
	}

	// Another request's result arrives (e.g. a policy deny): A stays shown.
	l.LogSign(&CallerContext{Name: "other"}, key, nil, EvalResult{Action: Deny}, nil)
	st = readCurrent(t, stateDir)
	if st.State != "confirming" || !strings.Contains(st.Text, "holder-a") {
		t.Fatalf("a finished request replaced the holder: %+v", st)
	}

	// A ends; its result is idle with B still counted.
	l.EndConfirming(id)
	l.LogSign(&CallerContext{Name: "holder-a"}, key, nil, EvalResult{Action: Allow}, nil)
	st = readCurrent(t, stateDir)
	if st.State != "idle" || !strings.Contains(st.Text, "1 waiting for YubiKey") {
		t.Fatalf("after the holder ended: %+v", st)
	}

	// A stale EndConfirming does not clear a newer holder.
	l.AddWaiting(-1)
	idB := l.SetConfirming(&CallerContext{Name: "holder-b"}, key, nil, touch)
	l.EndConfirming(id)
	l.LogSign(&CallerContext{Name: "holder-a"}, key, nil, EvalResult{Action: Allow}, nil)
	if st = readCurrent(t, stateDir); !strings.Contains(st.Text, "holder-b") {
		t.Fatalf("stale end cleared the holder: %+v", st)
	}
	l.EndConfirming(idB)
}

// While the YubiKey works for a request (ykchalresp running), the bar
// names that request: each concurrent request is seen confirming exactly
// while it holds the key.
func TestTouchApprovesTheRequestShown(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	l := NewLogger(stateDir, nil)
	key := testKey(t)
	seen := filepath.Join(dir, "seen")
	os.Mkdir(seen, 0700)
	info := filepath.Join(dir, "ykinfo")
	chal := filepath.Join(dir, "ykchalresp")
	os.WriteFile(info, []byte("#!/bin/sh\necho 'serial: 11583827'\n"), 0700)
	// Record the bar as the key sees it, then answer.
	os.WriteFile(chal, []byte("#!/bin/sh\ncp "+filepath.Join(stateDir, "current.yaml")+" "+seen+"/$$\nsleep 0.05\necho expected\n"), 0700)
	os.WriteFile(filepath.Join(dir, "11583827.response"), []byte("expected\n"), 0600)
	old := resolvedBinsVal.Load()
	resolvedBinsVal.Store(&resolvedBins{ykinfo: info, ykchalresp: chal})
	t.Cleanup(func() { resolvedBinsVal.Store(old) })
	cfg := DefaultConfirmConfig()
	cfg.ResponseDir = dir
	cfg.DenyPath = filepath.Join(dir, "deny")

	names := []string{"req-a", "req-b", "req-c"}
	done := make(chan bool, len(names))
	for _, name := range names {
		go func() {
			caller := &CallerContext{Name: name}
			result := EvalResult{Action: Confirm, ConfirmMethod: "touch"}
			var id uint64
			l.AddWaiting(1)
			turn := &confirmTurn{
				start: func() {
					id = l.StartTouch(caller, key, nil, result)
				},
				end: func() { l.EndConfirming(id) },
			}
			ok, _ := cfg.confirmHMAC(context.Background(), turn)
			l.LogSign(caller, key, nil, EvalResult{Action: Allow}, nil)
			done <- ok
		}()
	}
	for range names {
		if !<-done {
			t.Fatal("a confirmation failed")
		}
	}
	entries, _ := os.ReadDir(seen)
	if len(entries) != len(names) {
		t.Fatalf("ykchalresp ran %d times, want %d", len(entries), len(names))
	}
	shown := map[string]int{}
	for _, e := range entries {
		var st currentStatus
		data, _ := os.ReadFile(filepath.Join(seen, e.Name()))
		yaml.Unmarshal(data, &st)
		if st.State != "confirming" {
			t.Fatalf("key in use while the bar was %q: %q", st.State, st.Text)
		}
		for _, n := range names {
			if strings.Contains(st.Text, n) {
				shown[n]++
			}
		}
	}
	for _, n := range names {
		if shown[n] != 1 {
			t.Errorf("%s shown during %d key uses, want 1 (%v)", n, shown[n], shown)
		}
	}
}

// watchHangup cancels when the client closes, not on pending data or a
// half-close.
func TestWatchHangup(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "s")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	pair := func() (server, client net.Conn) {
		accepted := make(chan net.Conn, 1)
		go func() {
			c, _ := ln.Accept()
			accepted <- c
		}()
		client, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		return <-accepted, client
	}
	watch := func(server net.Conn) context.Context {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		go watchHangup(ctx, server, cancel)
		return ctx
	}

	t.Run("close cancels", func(t *testing.T) {
		server, client := pair()
		defer server.Close()
		ctx := watch(server)
		client.Close()
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
			t.Fatal("hangup not detected")
		}
	})
	t.Run("pending data and half-close do not", func(t *testing.T) {
		server, client := pair()
		defer server.Close()
		defer client.Close()
		ctx := watch(server)
		client.Write([]byte("unread request"))
		client.(*net.UnixConn).CloseWrite()
		select {
		case <-ctx.Done():
			t.Fatal("cancelled without a hangup")
		case <-time.After(700 * time.Millisecond):
		}
	})
}

// When a touch times out, confirmHMAC returns only after the killed
// ykchalresp has exited and been reaped, so the key is free for the next
// request when the lock passes.
func TestTimedOutYkchalrespReapedBeforeReturn(t *testing.T) {
	for _, how := range []string{"timeout", "deny"} {
		t.Run(how, func(t *testing.T) {
			dir := t.TempDir()
			pidFile := filepath.Join(dir, "pid")
			info := filepath.Join(dir, "ykinfo")
			chal := filepath.Join(dir, "ykchalresp")
			os.WriteFile(info, []byte("#!/bin/sh\necho 'serial: 11583827'\n"), 0700)
			os.WriteFile(chal, []byte("#!/bin/sh\necho $$ > "+pidFile+"\nexec sleep 5\n"), 0700)
			os.WriteFile(filepath.Join(dir, "11583827.response"), []byte("expected\n"), 0600)
			old := resolvedBinsVal.Load()
			resolvedBinsVal.Store(&resolvedBins{ykinfo: info, ykchalresp: chal})
			t.Cleanup(func() { resolvedBinsVal.Store(old) })
			cfg := DefaultConfirmConfig()
			cfg.ResponseDir = dir
			cfg.DenyPath = filepath.Join(dir, "deny")
			if how == "timeout" {
				cfg.Timeout = 1500 * time.Millisecond // room for a slow build host
			} else {
				go func() {
					for {
						if _, err := os.Stat(pidFile); err == nil {
							os.WriteFile(cfg.DenyPath, nil, 0600)
							return
						}
						time.Sleep(10 * time.Millisecond)
					}
				}()
			}
			if ok, _ := cfg.confirmHMAC(context.Background(), nil); ok {
				t.Fatal("confirmed without an answer")
			}
			data, err := os.ReadFile(pidFile)
			if err != nil {
				t.Fatal(err)
			}
			var pid int
			fmt.Sscan(strings.TrimSpace(string(data)), &pid)
			if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
				t.Fatalf("ykchalresp pid %d still exists after return (kill 0: %v)", pid, err)
			}
		})
	}
}

// A config reload leaves a confirming request on the bar.
func TestReloadKeepsHolder(t *testing.T) {
	stateDir := t.TempDir()
	l := NewLogger(stateDir, nil)
	id := l.SetConfirming(&CallerContext{Name: "holder"}, testKey(t), nil, EvalResult{Action: Confirm, ConfirmMethod: "touch"})
	l.NotifyReload()
	if st := readCurrent(t, stateDir); st.State != "confirming" || !strings.Contains(st.Text, "holder") {
		t.Fatalf("reload replaced the holder: %q %q", st.State, st.Text)
	}
	l.EndConfirming(id)
	l.NotifyReload()
	if st := readCurrent(t, stateDir); st.State != "reloaded" {
		t.Fatalf("reload with nothing confirming: %q", st.State)
	}
}

// A PIN prompt never takes the bar from the touch holder; once the holder
// ends, the pending PIN prompt is shown.
func TestPINDoesNotReplaceTouchHolder(t *testing.T) {
	stateDir := t.TempDir()
	l := NewLogger(stateDir, nil)
	key := testKey(t)
	touchID := l.SetConfirming(&CallerContext{Name: "touch-req"}, key, nil, EvalResult{Action: Confirm, ConfirmMethod: "touch"})
	pinID := l.SetConfirming(&CallerContext{Name: "pin-req"}, key, nil, EvalResult{Action: Confirm, ConfirmMethod: "pin"})
	if st := readCurrent(t, stateDir); !strings.Contains(st.Text, "touch-req") {
		t.Fatalf("PIN request replaced the touch holder: %q", st.Text)
	}
	l.EndConfirming(touchID)
	l.LogSign(&CallerContext{Name: "touch-req"}, key, nil, EvalResult{Action: Allow}, nil)
	if st := readCurrent(t, stateDir); st.State != "confirming" || !strings.Contains(st.Text, "pin-req") {
		t.Fatalf("pending PIN prompt not shown after the holder: %q %q", st.State, st.Text)
	}
	l.EndConfirming(pinID)
}

// Renderer runs never overlap, and a hung renderer is cut off.
func TestRenderSerializedAndBounded(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "render")
	os.WriteFile(bin, []byte("#!/bin/sh\nmkdir "+dir+"/running 2>/dev/null || echo x >> "+dir+"/overlaps\nsleep 0.02\nrmdir "+dir+"/running\n"), 0700)
	l := NewLogger(filepath.Join(dir, "state"), nil)
	l.renderBin = bin
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); l.render() }()
	}
	wg.Wait()
	if _, err := os.Stat(filepath.Join(dir, "overlaps")); err == nil {
		t.Fatal("renderer runs overlapped")
	}

	os.WriteFile(bin, []byte("#!/bin/sh\nexec sleep 30\n"), 0700)
	old := renderTimeout
	renderTimeout = 200 * time.Millisecond
	t.Cleanup(func() { renderTimeout = old })
	start := time.Now()
	l.render()
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("hung renderer held render for %s", d)
	}
}
