# Contributing

**ssh-agent-guard is beta software** recently extracted from a personal
configuration repository. There may still be assumptions about the
author's environment (NixOS, sway, tmux, YubiKey) that should be
generalized. Bug reports and patches for these are especially welcome.

## Building

```bash
make build    # or: go build -ldflags="-s -w" -o ssh-agent-guard .
make test     # runs tests with -race
make cross    # cross-compiles for x86_64 and aarch64
```

With Nix:
```bash
nix build
```

## Testing

```bash
# Run all tests
go test -race -count=1 ./...

# Debug policy matching against your current shell
./ssh-agent-guard check

# Check a specific PID
./ssh-agent-guard check --pid 12345 --key SHA256:abc123
```

## Code structure

All code is in the `main` package (single binary):

| File | Purpose |
|------|---------|
| `main.go` | Entry point, daemon loop, signal handling |
| `proxy.go` | SSH agent protocol proxy |
| `policy.go` | YAML policy engine, rule compilation, inotify reload |
| `caller.go` | Process identification (SO_PEERCRED, /proc) |
| `session.go` | Session binding, forwarding detection |
| `confirm.go` | YubiKey HMAC and display detection |
| `confirm_pin.go` | Remote confirmation (FIFO-based tmux popup) |
| `logger.go` | Structured YAML + journald logging |
| `check.go` | Debug/check mode |

Helper scripts in `scripts/` are installed alongside the binary.

## Documentation

Documentation is built from markdown sources using m4 (for shared
fragments) and go-md2man (for man page generation).

**Source files:**
- `docs/*.md` — shared fragments (requirements, threat model, etc.)
- `man/*.md.m4` — man page templates (markdown + m4 includes)
- `README.md.m4` — README template

**Generated files** (checked into git):
- `README.md` — generated from `README.md.m4` + `docs/`
- `ssh-agent-guard.1` — generated from `man/ssh-agent-guard.1.md.m4`
- `ssh-agent-guard-policy.5` — generated from `man/ssh-agent-guard-policy.5.md.m4`

**Editing:** Change the sources in `docs/` or `man/`, then regenerate:

```bash
nix develop -c make docs   # or: make docs (if m4 and go-md2man are in PATH)
man ./ssh-agent-guard.1    # preview
```

**Do not edit** `README.md`, `ssh-agent-guard.1`, or
`ssh-agent-guard-policy.5` directly — they will be overwritten by
`make docs`.

## Submitting changes

1. Fork and create a feature branch
2. Ensure `make test` passes
3. Keep commits focused — one logical change per commit
4. Open a pull request with a description of what and why

## Security

If you find a security issue, **do not** open a public issue. See
[SECURITY.md](SECURITY.md) for reporting instructions.
