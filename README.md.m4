changequote([[[,]]])dnl
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
- **YAML policy engine** with match fields (process_name, parent_process_name, ancestor,
  ssh_dest, is_forwarded, forwarded_via,
  is_in_known_hosts, is_in_container, env, cwd, ...)
- **YubiKey confirmation** — touch (local display) and PIN entry
  (via tmux popup)
- **Forwarded agent detection** via session-bind@openssh.com with
  known_hosts reverse lookup
- **Structured audit logging** — YAML event files + journald
- **Status bar integration** — i3status-rs and tmux
- **Container/PID namespace detection**
- **Read-only** — all key mutation operations (add, remove, lock,
  unlock) are unconditionally blocked

## Threat model

include([[[docs/threat-model.md]]])

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

include([[[docs/system-setup.md]]])

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

include([[[docs/requirements.md]]])

## YubiKey setup

include([[[docs/yubikey-setup.md]]])

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
