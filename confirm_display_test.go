package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSwaySocketCandidatesPrefersInheritedThenNewest(t *testing.T) {
	runtimeDir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	older := filepath.Join(runtimeDir, "sway-ipc.1000.10.sock")
	newer := filepath.Join(runtimeDir, "sway-ipc.1000.20.sock")
	for _, path := range []string{older, newer} {
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	oldTime := time.Unix(1, 0)
	newTime := time.Unix(2, 0)
	if err := os.Chtimes(older, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(newer, newTime, newTime); err != nil {
		t.Fatal(err)
	}

	inherited := filepath.Join(runtimeDir, "inherited.sock")
	want := []string{inherited, newer, older}
	if got := swaySocketCandidates(inherited); !reflect.DeepEqual(got, want) {
		t.Fatalf("got candidates %v, want %v", got, want)
	}
	want = []string{older, newer}
	if got := swaySocketCandidates(older); !reflect.DeepEqual(got, want) {
		t.Fatalf("got deduplicated candidates %v, want %v", got, want)
	}
}

func TestFindActiveSwaySocketFallsBackFromStaleInheritedSocket(t *testing.T) {
	candidates := []string{"stale-inherited", "stale-runtime", "live-runtime"}
	var probed []string
	probe := func(_ context.Context, _ string, socket string) error {
		probed = append(probed, socket)
		if socket == "live-runtime" {
			return nil
		}
		return os.ErrNotExist
	}

	got, err := findActiveSwaySocketFrom(context.Background(), "swaymsg", candidates, probe)
	if err != nil {
		t.Fatal(err)
	}
	if got != "live-runtime" {
		t.Fatalf("got socket %q, want live-runtime", got)
	}
	want := []string{"stale-inherited", "stale-runtime", "live-runtime"}
	if len(probed) != len(want) {
		t.Fatalf("probed %v, want %v", probed, want)
	}
	for i := range want {
		if probed[i] != want[i] {
			t.Fatalf("probed %v, want %v", probed, want)
		}
	}
}

func TestSwaylockIsActiveRequiresReadyMarkerAndHeldLock(t *testing.T) {
	runtimeDir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	marker := filepath.Join(runtimeDir, "swaylock-active")
	lockPath := filepath.Join(runtimeDir, "lock.sh.lock")
	if err := os.WriteFile(marker, []byte("123\n"), 0600); err != nil {
		t.Fatal(err)
	}
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lockFile.Close()

	if swaylockIsActive() {
		t.Fatal("free lock was reported active")
	}
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer unix.Flock(int(lockFile.Fd()), unix.LOCK_UN) //nolint:errcheck
	if !swaylockIsActive() {
		t.Fatal("ready marker with held lock was reported inactive")
	}
}

func TestIsSwaylockExecutableRecognizesNixWrapper(t *testing.T) {
	for _, path := range []string{
		"/usr/bin/swaylock",
		"/nix/store/example-swaylock/bin/.swaylock-wrapped",
		"/nix/store/example-swaylock/bin/.swaylock-wrapped (deleted)",
	} {
		if !isSwaylockExecutable(path) {
			t.Errorf("did not recognize %q", path)
		}
	}
	if isSwaylockExecutable("/usr/bin/not-swaylock") {
		t.Fatal("recognized unrelated executable")
	}
}

func TestHasUsableSwayOutput(t *testing.T) {
	tests := []struct {
		name     string
		outputs  string
		excluded string
		want     bool
		wantErr  bool
	}{
		{
			name:    "active output with power omitted",
			outputs: `[{"name":"DP-1","active":true}]`,
			want:    true,
		},
		{
			name:    "powered output",
			outputs: `[{"name":"DP-1","active":true,"power":true}]`,
			want:    true,
		},
		{
			name:    "powered off output",
			outputs: `[{"name":"DP-1","active":true,"power":false}]`,
		},
		{
			name:     "excluded active output",
			outputs:  `[{"name":"DSI-1","active":true},{"name":"DP-1","active":false}]`,
			excluded: " HDMI-A-1, DSI-1 ",
		},
		{
			name:     "other active output is usable",
			outputs:  `[{"name":"DSI-1","active":true},{"name":"DP-1","active":true}]`,
			excluded: "DSI-1",
			want:     true,
		},
		{
			name:    "malformed response",
			outputs: `{`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hasUsableSwayOutput([]byte(tt.outputs), tt.excluded)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
