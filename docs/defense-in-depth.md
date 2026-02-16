# Defense in depth

ssh-agent-guard adds access control and visibility to your SSH agent,
but it works best as one layer in a broader security setup.  This
page covers what you should do independently of (or in addition to)
the guard.

## Use hardware-backed keys

Store your SSH private keys on a hardware token (YubiKey, SoloKey,
Nitrokey) or in a hardware enclave rather than as files on disk.
This prevents key extraction even if your machine is fully
compromised.

- **FIDO2/resident keys** (`ssh-keygen -t ed25519-sk`) — the
  simplest option on OpenSSH 8.2+.  The private key never leaves
  the token.  Each operation requires a physical touch.
- **GPG-agent with a smartcard** — stores keys on a YubiKey's
  OpenPGP applet.  More complex setup but supports subkeys and
  expiration.

Hardware keys protect the key *material*.  ssh-agent-guard protects
the *use* of those keys — because even a non-extractable key can be
used by any process that can reach the agent socket.

## Disable agent forwarding by default

Agent forwarding (`ssh -A`) gives the remote host full access to
your local keys.  The ssh(1) man page explicitly warns against it:

> Agent forwarding should be enabled with caution.  Users with the
> ability to bypass file permissions on the remote host (for the
> agent's UNIX-domain socket) can access the local agent through
> the forwarded connection.

Instead of forwarding:

- **Use `ProxyJump`** (`ssh -J jumphost target`) — this chains
  connections through your local machine without exposing the
  agent to the jump host.
- **Forward only when needed** — use `ForwardAgent` per-host in
  `~/.ssh/config` rather than globally, and only for hosts you
  control.
- **Combine with ssh-agent-guard** — if you must forward, the
  guard's `is_forwarded` and `is_in_known_hosts` policy fields
  let you restrict which remote destinations can use your keys.

## Use separate keys for separate purposes

Don't use one key for everything.  Separate keys let you limit
blast radius:

- A deploy key for CI/CD (restricted to specific repos)
- A personal key for interactive SSH
- A key per client or employer

ssh-agent-filter can restrict which keys are *visible* per
connection.  ssh-agent-guard can restrict who can *use* each key
(via the `key:` match field).

## Protect the upstream socket

By default, any process running as your user can connect directly
to the SSH agent socket, bypassing ssh-agent-guard entirely.

The baseline approach is to put the real agent socket in a 0700
directory.  This prevents other users from reaching it, but same-user
processes can still traverse it — the defense is that they don't know
the path.

For stronger, kernel-enforced isolation, Linux offers several options
that restrict per-process file access without a separate user:
Landlock (unprivileged, no root needed), systemd
`InaccessiblePaths=`, AppArmor/SELinux, and mount namespaces.  See
[system setup](system-setup.md) for details and examples.

## Keep OpenSSH updated

OpenSSH 8.9+ sends `session-bind@openssh.com`, which is what
enables ssh-agent-guard's forwarding detection.  Older versions
work but without destination identification or forwarding
awareness.

## Restrict key types

Use Ed25519 keys.  They're fast, have no known weaknesses, and
have a fixed key size (no risk of accidentally generating a weak
key).  Avoid RSA keys shorter than 3072 bits and DSA entirely.

## Audit your authorized_keys

Periodically review `~/.ssh/authorized_keys` on your servers.
Old or forgotten keys are a common entry point.  Consider using
SSH certificates with short lifetimes instead of long-lived
authorized_keys entries.
