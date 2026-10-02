package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

type DoctorCmd struct {
	Touch bool `help:"Verify the enrolled HMAC response (requires touching the key)." name:"touch"`
}

func (c *DoctorCmd) Run(cli *CLI) error {
	return runDoctor(cli, c.Touch, os.Stdout)
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func enrollmentInstructions(w io.Writer, cfg ConfirmConfig, serial string) {
	path := filepath.Join(cfg.ResponseDir, serial+".response")
	fmt.Fprintln(w, "Enroll the existing HMAC slot (touch the key when it blinks):")
	fmt.Fprintf(w, "  mkdir -p %s\n", shellQuote(cfg.ResponseDir))
	fmt.Fprintf(w, "  response=$(ykchalresp %s %s) &&\n", shellQuote("-"+cfg.Slot), shellQuote(cfg.Challenge))
	fmt.Fprintf(w, "    printf '%%s\\n' \"$response\" | (umask 077; set -C; cat > %s)\n", shellQuote(path))
	fmt.Fprintln(w, "This preserves the key's existing slot configuration. Retry SSH after enrollment; no daemon restart is needed.")
}

func runDoctor(cli *CLI, touch bool, w io.Writer) error {
	issues := 0
	fail := func(format string, args ...any) { issues++; fmt.Fprintf(w, "FAIL: "+format+"\n", args...) }
	policy, loaded := NewPolicy(cli.Policy)
	if !loaded.OK {
		return fmt.Errorf("policy: %s", strings.Join(loaded.Errors, "; "))
	}
	fmt.Fprintf(w, "Policy: %s\n", cli.Policy)
	cfg := policy.ConfirmConfig()
	cfg.ResponseDir = filepath.Join(cli.StateDir, "confirm")
	cfg.DenyPath = filepath.Join(cfg.ResponseDir, "denied")
	fmt.Fprintf(w, "Touch confirmation: slot %s, challenge %s, timeout %s\n", cfg.Slot, cfg.Challenge, cfg.Timeout)
	for _, socket := range []struct{ name, path string }{{"guard", cli.Listen}, {"upstream", cli.Upstream}} {
		conn, err := net.DialTimeout("unix", socket.path, time.Second)
		if err != nil {
			fail("%s socket %s: %v", socket.name, socket.path, err)
			continue
		}
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		keys, err := agent.NewClient(conn).List()
		conn.Close()
		if err != nil {
			fail("%s agent cannot list keys: %v", socket.name, err)
		} else if len(keys) == 0 {
			fail("%s agent has no SSH keys; check gpg --card-status", socket.name)
		} else {
			fmt.Fprintf(w, "OK: %s agent lists %d key(s)\n", socket.name, len(keys))
		}
	}
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != cli.Listen {
		fmt.Fprintf(w, "NOTE: SSH_AUTH_SOCK=%s; use %s for guarded SSH\n", sock, cli.Listen)
	}
	bins := getResolvedBins()
	for _, bin := range []string{bins.ykinfo, bins.ykchalresp} {
		if _, err := exec.LookPath(bin); err != nil {
			fail("required tool unavailable: %s", bin)
		}
	}
	serial := cfg.getSerial()
	if serial == "" {
		fail("YubiKey not detected via USB HID; connect the key and check USB permissions (OpenPGP access alone is insufficient)")
	} else {
		fmt.Fprintf(w, "OK: connected YubiKey %s\n", serial)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		out, err := exec.CommandContext(ctx, bins.ykinfo, "-"+cfg.Slot).CombinedOutput()
		cancel()
		slotReady := err == nil && strings.TrimSpace(string(out)) == "slot"+cfg.Slot+"_status: 1"
		if !slotReady {
			fail("HMAC slot %s is unavailable or empty; inspect with ykman otp info. Configure HMAC with touch only after checking what this slot currently contains", cfg.Slot)
		}
		expected := cfg.loadExpectedResponse(serial)
		if expected == "" {
			fail("YubiKey %s is not enrolled: expected %s", serial, filepath.Join(cfg.ResponseDir, serial+".response"))
			if slotReady {
				enrollmentInstructions(w, cfg, serial)
			}
		} else if !regexp.MustCompile(`^[0-9a-fA-F]{40}$`).MatchString(expected) {
			fail("enrollment response is malformed; expected 40 hexadecimal characters")
		} else {
			fmt.Fprintln(w, "OK: enrollment response exists (use --touch to verify it against the key)")
			if touch {
				fmt.Fprintln(w, "Touch the YubiKey when it blinks.")
				if ok, reason := cfg.confirmHMAC(context.Background()); !ok {
					fail("%s", reason)
				} else {
					fmt.Fprintln(w, "OK: enrolled HMAC response verified")
				}
			}
		}
	}
	if issues > 0 {
		return fmt.Errorf("doctor found %d problem(s)", issues)
	}
	fmt.Fprintln(w, "Checks passed. OpenPGP signing and remote PIN confirmation were not tested.")
	return nil
}
