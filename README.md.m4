changequote([[[,]]])dnl
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
  (pango markup) and tmux (user option `@ssh_ag_status`)

## Requirements

include([[[docs/requirements.md]]])

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
