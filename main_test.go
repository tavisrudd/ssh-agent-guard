package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestMain keeps every test away from the real YubiKey and desktop: the
// system bin dirs and the front of PATH hold stubs that fail, so a test
// that does not stub a binary itself (NewPolicy re-resolves them) gets a
// failure, not the connected key, sway or the real status renderer.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ssh-ag-test-bins")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, name := range []string{"ykinfo", "ykchalresp", "swaymsg", "ssh-ag-render-status"} {
		script := "#!/bin/sh\necho 'test stub: no real " + name + "' >&2\nexit 1\n"
		if name == "ssh-ag-render-status" {
			script = "#!/bin/sh\nexit 0\n"
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	systemBinDirs = []string{dir}
	os.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// A policy load (which re-resolves the binaries) still finds the stubs.
func TestRealYubiKeyUnreachable(t *testing.T) {
	old := resolvedBinsVal.Load()
	t.Cleanup(func() { resolvedBinsVal.Store(old) })
	resolveBins()
	bins := getResolvedBins()
	for _, p := range []string{bins.ykinfo, bins.ykchalresp, findBin("swaymsg")} {
		if filepath.Dir(p) != systemBinDirs[0] {
			t.Errorf("%s is not a test stub", p)
		}
	}
}
