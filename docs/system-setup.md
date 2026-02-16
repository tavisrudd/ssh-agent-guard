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
