# ssh-agent-guard

> **Beta software.** ssh-agent-guard was recently extracted from a
> personal dotfiles repository. It works and has a test suite, but it
> has not had an independent security review and may still contain
> assumptions about the author's environment. See
> [SECURITY.md](SECURITY.md) for details. Feedback and contributions
> welcome.

Policy-enforcing proxy for SSH agent signing operations.

ssh-agent-guard sits between SSH clients and your real SSH agent
(gpg-agent, ssh-agent, etc.), identifying each connecting process,
evaluating YAML policy rules, and optionally requiring physical
YubiKey confirmation — giving you visibility and control over what
signs with your SSH keys.

## Why

Any process running as your user can talk to your SSH agent and sign
with your keys. There's no built-in mechanism to know *what* is
signing, *where* it's signing to, or to require consent for sensitive
operations.

This matters more now that AI coding tools, untrusted scripts, and
forwarded agent sessions routinely have access to `SSH_AUTH_SOCK`.
Without a guard, a compromised process can silently sign for any
destination using any key your agent holds.

ssh-agent-guard interposes on the agent socket, identifies every
caller, and lets you write policy rules that allow, deny, or require
physical confirmation per request.

## Features

- **Caller identification** via SO_PEERCRED + /proc (process name,
  command line, ancestry, cwd, environment, tmux window)
- **YAML policy engine** with 15 match fields (caller, ancestor,
  ssh_dest, remote_dest, forwarded, container, env, cwd, ...)
- **YubiKey confirmation** — HMAC touch (local) and PIN entry
  (remote via tmux popup)
- **Forwarded agent detection** via session-bind@openssh.com with
  known_hosts reverse lookup
- **Structured audit logging** — YAML event files + journald
- **Status bar integration** — i3status-rs and tmux
- **Container/PID namespace detection**
- **Read-only** — all key mutation operations (add, remove, lock,
  unlock) are unconditionally blocked

## Threat model

ssh-agent-guard is designed to protect SSH signing keys on a Linux
workstation where the user runs a mix of trusted and less-trusted
software under the same Unix account.

### What it protects against

- **Unauthorized local signing** — a compromised or untrusted process
  (AI coding tool, downloaded script, browser exploit) attempts to sign
  with your SSH key.  The proxy identifies the caller and applies policy
  rules to allow, deny, or require physical confirmation.
- **Forwarded agent abuse** — a remote host you SSH into attempts to
  use your forwarded agent to sign for destinations you didn't intend.
  The proxy intercepts `session-bind@openssh.com` to detect forwarding
  and can restrict which remote destinations are permitted.
- **Key management tampering** — a process attempts to add, remove,
  lock, or unlock keys on your agent.  All mutation operations are
  unconditionally blocked.
- **Silent signing** — without the proxy, any signing operation is
  invisible.  The proxy logs every sign request with full caller context
  (process name, command line, ancestry, working directory, environment)
  to structured YAML files and journald.

### What it does NOT protect against

- **Same-user socket access** (without system hardening) — by default,
  any process running as your user can connect directly to the upstream
  agent socket, bypassing the proxy entirely.  See the system setup
  section for filesystem-level protections that close this gap.
- **Root compromise** — a root-level attacker can read any socket,
  ptrace any process, and bypass all user-level controls.
- **TOCTOU** (time-of-check-time-of-use) — caller identity is gathered
  at connect(2) time via SO_PEERCRED.  If a process calls exec(2)
  between connecting and signing, the policy evaluation uses the
  pre-exec identity.  In practice this is a narrow window (microseconds)
  and requires a process specifically designed to exploit it.
- **YubiKey coercion** — if confirmation is required and an attacker has
  physical access to your YubiKey (or can socially engineer you into
  touching it), the confirmation can be bypassed.
- **/proc races** — the proxy reads /proc/$pid/\* after obtaining the PID
  via SO_PEERCRED.  If the PID is recycled before the reads complete,
  the proxy may read stale or wrong process information.  PID recycling
  attacks require precise timing and are impractical on systems with
  large PID ranges (kernel.pid_max).
- **Container callers with incomplete identity** — a container process
  with access to the socket (via bind mount) can connect, but its /proc
  entries may be invisible or in a different PID namespace.  The proxy
  detects PID namespace mismatches and marks such callers as
  `container=true`, but the caller identity fields (name, command,
  ancestry) may be unavailable.  Policy rules should default to deny or
  confirm for container callers.

### Without socket protection

Even without filesystem hardening, the proxy provides substantial value:

- **Audit logging** of all signing operations with full caller context
- **Physical confirmation** via YubiKey for sensitive operations
- **Policy enforcement** for all well-behaved software that respects
  `SSH_AUTH_SOCK` (ssh, git, rsync, and nearly all SSH clients)
- **Mutation blocking** (add/remove/lock/unlock always denied)

Most real-world threats (AI coding tools, scripts, forwarded sessions)
use `SSH_AUTH_SOCK` and will be subject to the proxy's policy.  Direct
socket access requires deliberately discovering and connecting to the
upstream path.


## Quick start

```bash
# Build
make

# Run with defaults (listens on $XDG_RUNTIME_DIR/ssh-agent-guard.sock)
./ssh-agent-guard

# Point SSH clients at the guard
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/ssh-agent-guard.sock"

# Test it
ssh-add -l            # list keys (proxied through)
ssh git@github.com    # sign request (logged, policy-evaluated)
```

### Write a policy

```bash
mkdir -p ~/.config/ssh-ag
cp examples/policy.yaml ~/.config/ssh-ag/policy.yaml
# Edit to taste — the proxy watches for changes via inotify
```

### Debug policy matching

```bash
# See how the proxy views your current shell
./ssh-agent-guard --check

# Check a specific process and key
./ssh-agent-guard --check --pid 12345 --key SHA256:abc123
```

## System setup

To be effective, the proxy must be the *only* path to the SSH agent
for untrusted processes.  This requires two things:

1. The upstream agent socket must be inaccessible to normal processes.
2. `SSH_AUTH_SOCK` must point to the proxy's listen socket.

### Socket protection with filesystem permissions

The strongest user-level approach uses directory permissions to hide the
upstream socket:

```bash
# Create a restricted directory for the real agent socket
mkdir -m 0700 "$XDG_RUNTIME_DIR/agent-upstream"

# Configure gpg-agent to use the restricted path
# (in ~/.gnupg/gpg-agent.conf, extra-socket directive)
extra-socket /run/user/1000/agent-upstream/S.gpg-agent.ssh

# Run the guard with access to the restricted socket
ssh-agent-guard \
    --listen "$XDG_RUNTIME_DIR/ssh-agent-guard.sock" \
    --upstream "$XDG_RUNTIME_DIR/agent-upstream/S.gpg-agent.ssh"

# Point clients at the guard
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/ssh-agent-guard.sock"
```

Other processes cannot traverse the restricted directory to reach the
real socket.

**Note:** This does not protect against root or processes with
CAP_DAC_READ_SEARCH.

### Minimal setup (without socket protection)

If you don't need hard isolation, simply interpose the proxy on the
default socket path:

```bash
ssh-agent-guard \
    --listen "$XDG_RUNTIME_DIR/gnupg/S.gpg-agent.ssh.guard" \
    --upstream "$XDG_RUNTIME_DIR/gnupg/S.gpg-agent.ssh"

export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/gnupg/S.gpg-agent.ssh.guard"
```

This provides logging, policy, and confirmation for all processes
that use `SSH_AUTH_SOCK`, but does not prevent direct access to the
upstream socket.


## Install

```bash
make install           # installs to /usr/local by default
make install PREFIX=~  # installs to ~/bin, ~/share/man
```

Or use the systemd service:
```bash
cp examples/ssh-agent-guard.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now ssh-agent-guard
```

## Helper scripts

- **ssh-ag-confirm** — remote confirmation via tmux popup (YubiKey
  PIN entry for sessions without a local display)
- **ssh-ag-deny** — cancel any pending confirmation (bind to a
  tmux/sway keybinding)
- **ssh-ag-render-status** — status bar renderer for i3status-rs
  (pango markup) and tmux (user option `@ssh_ag_status`)

## Requirements

- **Linux** — uses SO_PEERCRED(7), /proc, and PID namespaces.
  No macOS or BSD support.
- **OpenSSH 8.9+** — required for `session-bind@openssh.com`, which
  provides forwarded agent detection, destination host identification,
  and `remote_dest`/`remote_dest_in`/`forwarded` policy matching.
  Without it the guard still works but those fields are always empty.
- **Go 1.24+** — for building from source.

### Optional dependencies

- **yubikey-personalization** — provides `ykchalresp` and `ykinfo`,
  used for YubiKey HMAC confirmation.  When installed via the Nix flake,
  these are included in the wrapper's PATH.  Without a YubiKey,
  `action: confirm` rules degrade to `deny`.
- **tmux** — used for remote confirmation popups (`ssh-ag-confirm`
  runs in a tmux popup), status display (sets `@ssh_ag_status` user
  option), and remote session detection.
- **sway** — `hasActiveDisplay()` uses `swaymsg` to check compositor
  reachability and detect `swaylock`.  Other Wayland/X11 compositors
  would need equivalent logic.
- **jq** — used by `hasActiveDisplay()` to parse sway output JSON.
- **i3status-rs** — `ssh-ag-render-status` writes pango markup to a
  file watched by i3status-rs.  Other status bars would need a
  different renderer.

The core proxy (policy evaluation, caller identification, logging)
has no compositor or multiplexer dependencies — only the confirmation
UI and status rendering do.


## YubiKey setup

ssh-agent-guard uses YubiKey HMAC-Challenge slots for physical
confirmation of signing requests.  Two slots are used:

- **Slot 2** (default) — touch confirmation.  A fixed challenge is sent
  to the YubiKey; the user must physically touch the key to generate a
  response.  Used when a local display is active.
- **Slot 1** (default) — PIN confirmation.  The user's PIN is sent as
  the HMAC challenge; no touch required.  Used when no local display is
  active (remote sessions via tmux popup).

Slot numbers are configurable via the `confirm.touch.slot` and
`confirm.pin.slot` policy fields.  See ssh-agent-guard-policy(5).

### Linux permissions

`ykchalresp` and `ykinfo` communicate with the YubiKey over USB HID via
libusb.  This requires udev rules granting access to Yubico devices
(vendor ID 1050):

```bash
# NixOS (configuration.nix)
services.udev.packages = [ pkgs.yubikey-personalization ];

# Debian/Ubuntu
sudo apt install yubikey-personalization

# Manual udev rule
SUBSYSTEM=="usb", ATTRS{idVendor}=="1050", MODE="0660", GROUP="plugdev"
```

### Programming HMAC slots

Use `ykman` to program the HMAC-Challenge slots:

```bash
# Slot 2: touch confirmation (requires physical touch)
ykman otp chalresp --touch --generate 2

# Slot 1: PIN confirmation (no touch, responds immediately)
ykman otp chalresp --generate 1
```

### Registering the expected response

After programming the slots, generate and store the expected HMAC
response so the guard can verify the YubiKey's identity:

```bash
# Get YubiKey serial number
SERIAL=$(ykinfo -s | grep -o '[0-9]*')

# Generate expected response for slot 2 (touch — tap the key)
# Uses the challenge from your policy (default: "deadbeef")
RESPONSE=$(ykchalresp -2 deadbeef)

# Store it
mkdir -p ~/.local/state/ssh-ag/confirm
echo "$RESPONSE" > ~/.local/state/ssh-ag/confirm/${SERIAL}.response
```

For PIN confirmation (slot 1), response files use different naming;
the `ssh-ag-confirm` script handles this automatically.

The challenge string and slot numbers are configurable in the policy
file's `confirm:` section.  See ssh-agent-guard-policy(5).


## Documentation

Full documentation is also available as man pages:

- **ssh-agent-guard(1)** — daemon operation, options, caller
  identification, all sections above plus environment variables
  and file paths
- **ssh-agent-guard-policy(5)** — policy file format, match fields,
  examples, rule evaluation

```bash
man ./ssh-agent-guard.1
man ./ssh-agent-guard-policy.5
```

## Prior art

- [ssh-agent-filter](https://github.com/tiwe-de/ssh-agent-filter) —
  filtering proxy for ssh-agent, restricts by key fingerprint (C++)
- [guardian-agent](https://github.com/StanfordSNR/guardian-agent) —
  secure agent forwarding with per-session prompts (requires patched
  SSH client)
- [sshield](https://github.com/gotlougit/sshield) — sandboxed SSH
  agent replacement written in Rust
- OpenSSH `ssh-add -c` — built-in per-operation confirmation (no
  policy, no caller context, generic askpass dialog)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports for
environment-specific assumptions are especially welcome.

## License

BSD-3-Clause. See [LICENSE](LICENSE).
