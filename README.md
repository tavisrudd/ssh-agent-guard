# ssh-agent-guard

> **Beta.** Works and tested, but no independent security review yet.
> See [SECURITY.md](SECURITY.md) for known limitations.

**Any process running as your user can silently sign with your SSH keys.**
There's no built-in way to know *what* is signing, *where* it's signing
to, or to require your consent.

ssh-agent-guard is a proxy that sits between SSH clients and your real
agent, giving you visibility and control over every signing operation.
It identifies the connecting process, evaluates YAML policy rules, and
can optionally require physical YubiKey confirmation — so you know
exactly what's using your keys. No YubiKey? The proxy still identifies
callers, enforces policy, and logs everything.

### Who should use this

- You run **AI coding tools**, downloaded scripts, or other less-trusted
  software alongside your SSH keys
- You use **agent forwarding** and want to restrict which remote
  destinations can sign
- You want an **audit trail** of every SSH signing operation

## Features

- **Know who's signing** — see the exact process, its parent chain,
  working directory, and environment for every signing request
- **Write precise policies** — YAML rules that distinguish AI tools
  from git, restrict forwarded agents by destination, and match on
  process name, ancestry, container status, and more
- **Require physical confirmation** — YubiKey touch for local sessions,
  PIN entry via tmux popup for remote sessions (optional)
- **Prevent forwarded agent abuse** — detect when a remote host tries
  to sign for destinations you didn't intend
- **Audit everything** — every request logged to YAML files and journald
  with full caller context
- **Block key tampering** — add, remove, lock, and unlock operations are
  unconditionally denied
- **Monitor in real time** — see signing activity in your i3status-rs
  or tmux status bar

### Example policy

```yaml
rules:
  # Git hosting — always allow
  - name: git-hosts
    match:
      ssh_dest: "git@github.com"
    action: allow

  # AI coding tools — require YubiKey confirmation
  - name: ai-tools
    match:
      env:
        CLAUDECODE: "1"
    action: confirm

  # Forwarded agent to known hosts — allow
  - name: forwarded-known
    match:
      is_forwarded: true
      is_in_known_hosts: true
    action: allow

  # Forwarded agent to unknown hosts — deny
  - name: forwarded-unknown
    match:
      is_forwarded: true
    action: deny
```

Rules are evaluated top-to-bottom; first match wins. All fields in a
match section must match (AND logic). Omitted fields match anything.
See **ssh-agent-guard-policy(5)** for the full list of match fields.

### How it compares

| | ssh-agent-guard | `ssh-add -c` | ssh-agent-filter |
|---|---|---|---|
| Per-operation confirmation | Yes (YubiKey touch/PIN) | Yes (askpass dialog) | No |
| Caller identification | Full (process, ancestry, env) | None | None |
| Policy rules | YAML, flexible match fields | None | Key fingerprint only |
| Audit logging | Structured YAML + journald | None | None |
| Forwarded agent detection | Yes (session-bind) | No | No |

The key differentiator is caller identification — instead of a generic
"allow this operation?" prompt, you can write rules like "allow git to
sign for github.com, require confirmation for AI tools, deny
everything forwarded to unknown hosts."

See also: [guardian-agent](https://github.com/StanfordSNR/guardian-agent) (per-session prompts, requires patched SSH),
[sshield](https://github.com/gotlougit/sshield) (sandboxed agent replacement in Rust).

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

### Verify it's working

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
  The proxy intercepts `session-bind@openssh.com` (an OpenSSH protocol
  extension that notifies agents when SSH sessions are created) to
  detect forwarding and restrict which remote destinations are permitted.
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
- **Policy enforcement** for all software that uses `SSH_AUTH_SOCK`
  (ssh, git, rsync, and nearly all SSH clients)
- **Mutation blocking** (add/remove/lock/unlock always denied)

Most real-world threats (AI coding tools, scripts, forwarded sessions)
use `SSH_AUTH_SOCK` and will be subject to the proxy's policy.  Direct
socket access requires deliberately discovering and connecting to the
upstream path.


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
  enables forwarded agent detection and the `ssh_dest`,
  `is_in_known_hosts`, and `is_forwarded` policy fields.
  Without it the guard still works but cannot identify remote
  destinations or detect forwarding.
- **Go 1.24+** — for building from source.

### Optional dependencies

- **yubikey-personalization** — provides `ykchalresp` and `ykinfo`,
  used for YubiKey HMAC confirmation.  When installed via the Nix flake,
  these are included in the wrapper's PATH.  Without a YubiKey,
  `action: confirm` rules degrade to `deny`.
- **tmux** — used for PIN confirmation popups (`ssh-ag-confirm`
  runs in a tmux popup), status display (sets `@ssh_ag_status` user
  option), and forwarded session detection.
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

**A YubiKey is optional.** Without one, the proxy still identifies
callers, enforces policy, and logs everything. Rules with
`action: confirm` degrade to `deny` when no YubiKey is available.

If you have a YubiKey, the guard uses HMAC-Challenge (a
challenge-response protocol over USB) with two slots:

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

Full documentation is available as man pages:

- **ssh-agent-guard(1)** — daemon operation, options, caller
  identification, environment variables, file paths
- **ssh-agent-guard-policy(5)** — policy file format, all match fields,
  examples, rule evaluation order

```bash
man ssh-agent-guard
man ssh-agent-guard-policy
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports for
environment-specific assumptions are especially welcome.

## License

BSD-3-Clause. See [LICENSE](LICENSE).
