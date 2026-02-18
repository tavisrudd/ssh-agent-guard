changequote([[[,]]])dnl
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

  # Coding agents — require YubiKey confirmation
  # (detects Claude, Cursor, Copilot, Aider, Windsurf, Amp, Pi)
  - name: coding-agents
    match:
      is_coding_agent: true
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
./ssh-agent-guard check

# Check a specific process and key
./ssh-agent-guard check --pid 12345 --key SHA256:abc123
```

### What you see

**`check` output** shows how the proxy identifies your process and
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
    - name: coding-agents
      action: confirm
      matched: false
      mismatches: ["is_coding_agent: want true, got false"]
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

include([[[docs/system-setup.md]]])

## Threat model

include([[[docs/threat-model.md]]])

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

include([[[docs/requirements.md]]])
See [macOS support](docs/macos-support.md) for the full porting
analysis.

## YubiKey setup

**A YubiKey is optional.** Without one, the proxy still identifies
callers, enforces policy, and logs everything. Rules with
`action: confirm` degrade to `deny` when no YubiKey is available.

If you have a YubiKey, the guard uses HMAC-Challenge (a
challenge-response protocol over USB) with two slots:

include([[[docs/yubikey-setup.md]]])

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
