# ssh-agent-guard

> **Beta.** Works and tested, but no independent human security review
> has been performed — only multiple rounds of LLM/coding-agent reviews.
> See [SECURITY.md](SECURITY.md) for known limitations.

**Any process running as your user can silently use your SSH keys** —
to open connections, push to your repos, or authenticate as you to any
server.  The SSH agent protocol doesn't verify *who* is asking, *where*
they're connecting, or *why* — every request is a blank check.  Even
hardware keys that can't be extracted can still be used by anyone who
can reach the socket.

ssh-agent-guard is a proxy that sits between SSH clients and your real
agent, giving you visibility and control over every key operation.
It identifies the connecting process, evaluates policy rules, and
can optionally require physical YubiKey confirmation for sensitive
operations.  No YubiKey?  The proxy still identifies callers, enforces
policy, and logs everything.

### Who should use this

- You run **AI coding tools**, downloaded scripts, or other less-trusted
  software alongside your SSH keys
- You use **agent forwarding** and want to restrict which remote
  hosts can use your keys
- You want an **audit trail** of every SSH key operation

See [why this matters](docs/why-this-matters.md) for real-world
incidents and risk framework references.

## Features

- **Know who's using your keys** — catch malicious scripts and
  misbehaving tools before they authenticate or push code
  (process name, ancestry, env, working directory —
  [how it works](docs/caller-identification.md))
- **Write precise policies** — allow git to push without interruption,
  require confirmation for AI tools, block forwarded agents from
  reaching unknown hosts
  ([policy guide](docs/policy-guide.md))
- **Require physical confirmation** — YubiKey touch for local sessions,
  PIN entry via tmux popup for remote sessions (optional)
- **Prevent forwarded agent abuse** — stop a compromised remote host
  from using your keys to pivot to other systems
  ([how detection works](docs/forwarding.md))
- **See everything** — live status bar updates as keys are used,
  plus structured logs you can grep, alert on, or audit later
  (YAML files + journald)
- **Block key tampering** — prevent malware from loading its own keys
  onto your agent or removing yours
  (add/remove/lock/unlock unconditionally denied)

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
If no policy file exists, the proxy defaults to **confirm** for all
requests.  See **ssh-agent-guard-policy(5)** for the full list of match
fields.

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
ssh git@github.com    # key use logged, policy-evaluated
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

### What you see

**`--check` output** shows how the proxy identifies your process and
which rules match:

```yaml
context:
  process_name: bash
  cmdline: /bin/bash
  local_cwd: /home/alice/src/myproject
  is_forwarded_session: false
  is_container: false
  tmux_window: "main:code"
  env:
    TERM: xterm-256color
    TMUX_PANE: "%0"
  local_proc_tree:
    - pid: 3001
      name: bash
      cmd: /bin/bash
    - pid: 1200
      name: tmux
      cmd: tmux new-session -s main
policy_evaluation:
  policy_file: /home/alice/.config/ssh-ag/policy.yaml
  rules:
    - name: git-hosts
      action: allow
      matched: false
      mismatches: ["ssh_dest: empty, want git@github.com"]
    - name: ai-tools
      action: confirm
      matched: false
      mismatches: ["env.CLAUDECODE: empty, want 1"]
result:
  action: allow
  rule: default
```

**Log entry** for an allowed git push
(`~/.local/state/ssh-ag/20260215-143022-ssh.main:code-git@github.com-allow.yaml`):

```yaml
timestamp: "2026-02-15T14:30:22"
trigger: sign
process_name: ssh
local_pid: 4521
tmux_window: "main:code"
key_fingerprint: SHA256:abcdef1234567890abcdef1234567890abcdefgh
ssh_dest: git@github.com
local_cwd: /home/alice/src/myproject
is_forwarded_session: false
decision: allow
rule: git-hosts
local_proc_tree:
  - pid: 4521
    name: ssh
    command: ssh git@github.com git-receive-pack myproject.git
  - pid: 4520
    name: git
    command: git push origin main
  - pid: 3001
    name: bash
    command: /bin/bash
```

**Denied request** -- the SSH client sees "agent refused operation":

```
$ ssh suspect-host.example.com
sign_and_send_pubkey: signing failed for ED25519 "cardno:00 00"
  from agent: agent refused operation
alice@suspect-host.example.com: Permission denied (publickey).
```

**YubiKey touch confirmation** -- when a `confirm` rule matches in a
local session, the status bar shows `TOUCH YK` and the proxy waits
up to 20 seconds for you to tap the key.  Touch takes ~1 second.

**PIN confirmation** -- in a remote session (no local display), a
tmux popup appears asking for your PIN.  Enter it to approve, or
press the deny keybinding (bound to `ssh-ag-deny`) to reject.

## Day-to-day experience

**How often are you interrupted?** Only when a `confirm` rule
matches.  With a typical policy (allow git hosts, confirm AI tools,
deny forwarded-to-unknown), most key use is silent and instant.

- **Touch confirmation** takes ~1 second (tap YubiKey, done).
- **PIN confirmation** takes a few seconds (tmux popup, type PIN).
- **Denied requests** fail immediately -- SSH reports "agent refused
  operation" and you move on.
- **Policy changes** take effect instantly via inotify -- no restart,
  no reconnect.

If you just want visibility without interruptions, set
`default_action: allow` with no `confirm` rules.  Every key
operation is still logged with full caller context.

### How it compares

|                         | ssh-agent-guard | `ssh-add -c` | ssh-agent-filter | `ssh-add -h` (8.9+) |
|-------------------------|-----------------|--------------|------------------|----------------------|
| Caller identification   | Full ¹          | None         | None             | None                 |
| Per-operation confirm   | Yes ²           | Yes ³        | No               | No                   |
| Policy rules            | Yes ⁴           | None         | Key fingerprint  | Host allowlist       |
| Destination restriction | Yes             | No           | No               | Yes (built-in)       |
| Forwarded agent detect  | Yes ⁵           | No           | No               | Yes (protocol-level) |
| Scope                   | All key use ⁶   | All key use  | All key use      | SSH auth only        |
| Audit logging           | Yes ⁷           | None         | None             | None                 |

¹ Process name, ancestry, environment, working directory —
[how it works](docs/caller-identification.md).
² YubiKey HMAC touch (local) or PIN via tmux popup (remote).
³ SSH askpass dialog, no caller context.
⁴ Glob/regex on process, destination, environment, ancestry, and more —
[policy guide](docs/policy-guide.md).
⁵ Via [session-bind@openssh.com](docs/forwarding.md) (OpenSSH 8.9+).
⁶ SSH authentication, git commit signing, age encryption.
⁷ Structured YAML files + journald, with full caller context.

The key differentiator is caller identification — instead of a generic
"allow this operation?" prompt, you can write rules like "allow git to
connect to github.com, require confirmation for AI tools, deny
everything forwarded to unknown hosts."

**`ssh-add -c`** prompts for every operation identically — it can't
distinguish `git push` from a malicious script.  You either confirm
everything or nothing.

**ssh-agent-filter** controls which keys are *visible* per connection
but can't restrict *who uses them* or *where they connect*.  The two
tools are complementary: filter which keys are exposed, then guard
who can use each one.

**guardian-agent** (Stanford) is the closest in ambition — it verifies
destinations for forwarded sessions — but requires a patched OpenSSH
and is unmaintained.  ssh-agent-guard works with stock OpenSSH via
`session-bind@openssh.com`.

**OpenSSH destination constraints** (`ssh-add -h`, 8.9+) restrict
keys to specific hosts at the protocol level.  A significant
improvement, but limited to SSH authentication (not git signing or
age decryption), must be configured per-key at load time, and
cannot distinguish callers.

**Hardware keys** (YubiKey FIDO2, Secure Enclave) protect key material
from extraction, but any process that can reach the agent socket can
still use them.  ssh-agent-guard adds the missing access control layer.

See [defense in depth](docs/defense-in-depth.md) for how these
layers work together.

See also: [guardian-agent](https://github.com/StanfordSNR/guardian-agent),
[ssh-agent-filter](https://github.com/tiwe-de/ssh-agent-filter),
[sshield](https://github.com/gotlougit/sshield),
[Secretive](https://github.com/maxgoedjen/secretive).

## System setup

To be effective, the proxy must be the *only* path to the SSH agent
for untrusted processes.  This requires two things:

1. The upstream agent socket must be inaccessible to normal processes.
2. `SSH_AUTH_SOCK` must point to the proxy's listen socket.

### Socket protection with filesystem permissions

The simplest approach uses directory permissions to hide the upstream
socket:

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

**Limitation:** The 0700 directory prevents other *users* from
reaching the socket, but any process running as your UID can still
traverse it.  The practical defense here is obscurity: processes use
`SSH_AUTH_SOCK` (pointing to the proxy) and don't know the upstream
path.  For stronger per-process isolation, see below.

**Note:** This does not protect against root or processes with
CAP_DAC_READ_SEARCH.

### Stronger isolation with Linux sandboxing

Linux provides several mechanisms to enforce per-process access
control on the upstream socket, without requiring a separate user:

**Landlock** (Linux 5.13+) — an unprivileged LSM that lets a process
restrict its own filesystem access.  An untrusted process (or its
launcher) can drop access to the upstream socket directory before
executing.  No root required, no policy files — just syscalls.

**systemd sandboxing** — user service units support
`InaccessiblePaths=` which makes paths invisible to that service.
If you run AI tools or other untrusted software as systemd user
services, this is the easiest approach:

```ini
# ~/.config/systemd/user/untrusted-tool.service
[Service]
ExecStart=/usr/bin/some-ai-tool
InaccessiblePaths=/run/user/1000/agent-upstream
```

**AppArmor / SELinux** — mandatory access control policies can
restrict which executables or confined domains can access specific
paths.  AppArmor is common on Ubuntu/Debian; SELinux on Fedora/RHEL.

**Mount namespaces** — `unshare -m` creates a private mount namespace
where the upstream socket directory can be bind-mounted over or
unmounted entirely.  The guard runs in the host namespace; untrusted
processes run in a restricted namespace where the upstream socket
simply doesn't exist:

```bash
# Run an untrusted process without access to the upstream socket
unshare -m sh -c \
    'umount "$XDG_RUNTIME_DIR/agent-upstream" 2>/dev/null; exec "$@"' \
    -- some-untrusted-tool
```

These mechanisms range from lightweight (Landlock, systemd directives)
to comprehensive (SELinux, mount namespaces).  The 0700 directory is a
reasonable baseline; the above provide kernel-enforced per-process
isolation.

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

ssh-agent-guard is designed to control who can use your SSH keys on a
Linux workstation where you run a mix of trusted and less-trusted
software under the same Unix account.  Hardware keys (YubiKey, Secure
Enclave) prevent key extraction, but any process that can reach the
agent socket can still use your keys to open connections and
authenticate as you — ssh-agent-guard closes that gap.

### What it protects against

- **Unauthorized key use** — a compromised or untrusted process
  (AI coding tool, downloaded script, browser exploit) uses your SSH
  keys to open connections or authenticate.  The proxy identifies the
  caller and applies policy rules to allow, deny, or require physical
  confirmation.
- **Forwarded agent abuse** — a remote host you SSH into uses your
  forwarded agent to connect to destinations you didn't intend.
  The proxy intercepts `session-bind@openssh.com` (an OpenSSH protocol
  extension that notifies agents when SSH sessions are created) to
  detect forwarding and restrict which remote destinations are permitted.
- **Key management tampering** — a process attempts to add, remove,
  lock, or unlock keys on your agent.  All mutation operations are
  unconditionally blocked.
- **Silent key use** — without the proxy, any key operation is
  invisible.  The proxy logs every request with full caller context
  (process name, command line, ancestry, working directory, environment)
  to structured YAML files and journald.

### What it does NOT protect against

- **Same-user socket access** (without system hardening) — by default,
  any process running as your user can connect directly to the upstream
  agent socket, bypassing the proxy entirely.  A 0700 directory hides
  the socket from other users but not same-user processes.  Linux
  provides kernel-enforced per-process isolation (Landlock, systemd
  sandboxing, AppArmor/SELinux, mount namespaces) that can close this
  gap.  See the SYSTEM SETUP section.
- **Root compromise** — a root-level attacker can read any socket,
  ptrace any process, and bypass all user-level controls.
- **TOCTOU** (time-of-check-time-of-use) — caller identity is gathered
  once per connection at accept(2) time and not re-read on each sign
  request.  If a process calls exec(2) after identity is captured,
  subsequent sign requests use the stale (pre-exec) identity.  There
  is also a narrow race between connect(2) and the /proc reads where
  an exec could cause the proxy to see the post-exec identity instead.
  Both scenarios require a process specifically designed to exploit them.
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
  (pango markup) and tmux (user option `@ssh_ag_status`).
  Replaceable — see [status rendering](docs/status-rendering.md)
  for the interface contract and examples for other targets
  (desktop notifications, Waybar, polling-based)

## Requirements

- **Linux only** (macOS support planned) — uses `SO_PEERCRED(7)` for
  kernel-verified caller identification and `/proc` for process context
  (command line, ancestry, environment, PID namespaces).  macOS has
  equivalent APIs (`LOCAL_PEERPID`, `KERN_PROCARGS2`, `proc_pidinfo`)
  that enable a near-complete port.
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

### Performance

The proxy adds negligible latency (~1ms per operation).  The main
cost is `/proc` reads for caller identification, which are
memory-backed and fast on any modern kernel.

See [macOS support](docs/macos-support.md) for the full porting
analysis.

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
