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
