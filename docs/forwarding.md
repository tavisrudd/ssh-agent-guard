# Forwarded agent detection

When you SSH to a remote host with agent forwarding (`ssh -A`), the
remote host gains access to your SSH keys via the forwarded socket.
ssh-agent-guard detects this and lets you write policy rules that
restrict what forwarded agents can sign for.

## session-bind@openssh.com

OpenSSH 8.9+ sends a `session-bind@openssh.com` extension message to
the agent whenever an SSH session is established.  This message
contains:

1. **The destination host's public key** -- the server you're
   connecting to.
2. **A forwarding flag** -- whether the agent socket was forwarded
   from a previous hop.

The proxy verifies the host-key signature and records the ordered binding
chain. When the final binding is for authentication, a sign request is
accepted only when the complete signed user-authentication request matches
the requested user key and authenticated session. When the final binding is
for forwarding, only a pam_ssh_agent_auth challenge is accepted (see
[below](#sudo-via-pam_ssh_agent_auth)). Forwarded chains must use
OpenSSH hostbound authentication, whose embedded destination host key must
match the final binding. This prevents a forwarded client from inventing
destination metadata or applying it to a different connection.

### What this enables

With session-bind, the proxy can populate three policy fields:

- **`is_forwarded`** -- `true` when any earlier binding in the verified
  chain forwarded the agent (the remote host is using your agent, not your
  local machine).
- **`ssh_dest`** -- the hostname of the destination, resolved via
  known_hosts reverse lookup (see below).
- **`is_in_known_hosts`** -- whether the destination host key was
  found in your `~/.ssh/known_hosts`.

### Without session-bind

If your OpenSSH is older than 8.9, the proxy still works but cannot
identify remote destinations or detect forwarding.  The
`is_forwarded`, `ssh_dest` (for forwarded sessions), and
`is_in_known_hosts` fields will be unavailable.

### Session names carried to forwarded channels

OpenSSH opens a new agent connection for each forwarded agent channel
and binds it to the same session (same host key and session id) with
the forwarding flag set. That connection has no local command line
naming the destination. When the local `ssh` that authenticated the
session named its destination on the command line (`ssh or3.lan`), the
proxy remembers session id and host key → name in memory, and the
forwarded channel inherits it. The name feeds `ssh_dest` and logs but
not `is_in_known_hosts`. After a proxy restart the memory is empty and
forwarded sessions have no name.

## sudo via pam_ssh_agent_auth

A forwarded connection whose last binding is for forwarding cannot
carry a user-authentication request; the proxy denies everything on it
except a `pam_ssh_agent_auth` (0.10.x) challenge. The challenge layout
is:

```
string  session_id2:
          uint32 101, string cookie, string user, string ruser,
          string service, string cwd,
          string action (uint32 argc, argc × string argv; or empty),
          string hostname, uint64 timestamp
byte    54 (SSH2_MSG_USERAUTH_TRUST_REQUEST)
string  ruser
string  "pam_ssh_agent_auth"
string  "publickey"
bool    1
string  key algorithm
string  public key
```

A signature over this cannot log in anywhere (sshd verifies message 50
and service `ssh-connection`) and is not an SSHSIG. It satisfies only
the PAM module that minted the cookie. Everything inside it is written
by the remote side; only the session-bind destination is authenticated.
To stop a process on the remote host relaying a challenge from sudo on
some other host, the proxy denies a forwarded challenge whose hostname
(first label) differs from the destination's name, or when the
destination has no name, or when the timestamp is more than five
minutes off. Policy then sees `sign_kind: pam` and the `pam_service`,
`pam_command` and `pam_user` fields; see the
[policy guide](policy-guide.md#sudo-through-a-forwarded-agent-pam_ssh_agent_auth).

While a forwarded session is open, any process on the remote host
running as you or root can reach the forwarded socket. With
`action: confirm` every sudo needs a touch or PIN, and the status bar
shows the claimed command. The command is chosen by the requester, so
the label says *a* sudo is pending, not that it is the one you typed.

## known_hosts reverse lookup

The session-bind message contains the destination's host key, but not
its hostname.  To get a human-readable destination, the proxy
maintains a reverse index of `~/.ssh/known_hosts`: mapping key
fingerprints back to hostnames.

This is what makes rules like `ssh_dest: "*.example.com"` work for
forwarded sessions, where there's no local `ssh` command line to
parse.

### Hashed known_hosts

If you use `HashKnownHosts yes`, your known_hosts entries are
one-way HMAC-SHA1 hashes.  These cannot be reversed, so the proxy
skips them.  When all entries are hashed, `ssh_dest` (via
session-bind) and `is_in_known_hosts` won't work for forwarded
sessions.

**Workaround:** Maintain a plaintext known_hosts alongside the hashed
one using `UserKnownHostsFile` in your ssh_config:

```
# ~/.ssh/config
UserKnownHostsFile ~/.ssh/known_hosts ~/.ssh/known_hosts_plain
HashKnownHosts no  # for the second file
```

## ssh_dest fallback chain

The `ssh_dest` policy field is populated by a multi-step fallback:

1. **Local command line** -- parse the `ssh` command line of the
   connecting process or its ancestors for the destination argument
   (`ssh user@host`).
2. **session-bind + known_hosts** -- if no local command line is
   available (typical for forwarded sessions), use the session-bind
   host key fingerprint to look up the hostname in known_hosts.
3. **Empty** -- if neither source produces a result, `ssh_dest` is
   empty and won't match any pattern.

This means `ssh_dest` works transparently for both direct SSH
connections (via command line parsing) and forwarded sessions (via
session-bind).

## forwarded_via (mux socket parsing)

When SSH uses `ControlMaster` multiplexing, child connections go
through a mux process whose command line looks like:

```
ssh: /home/user/.ssh/sockets/host_22_user [mux]
```

The proxy parses the socket filename (which follows the
`ControlPath %h_%p_%r` convention) to extract the intermediate host.
This populates the `forwarded_via` policy field as `user@host`.

## Forwarded session detection

Separately from agent forwarding detection (which uses session-bind),
the proxy detects whether *the current shell session* is itself
remote.  This uses three heuristics:

1. **tmux global environment** -- if the caller is in tmux, check
   `tmux show-environment SSH_CONNECTION`.  This reflects the current
   attach state, unlike `/proc/pid/environ` which is frozen at
   process creation.
2. **Process environment** -- check for `SSH_CONNECTION` in
   `/proc/$pid/environ`.
3. **Ancestry** -- check for `sshd` in the process tree.

This is surfaced as `user_presence` (values: `local` or `remote`) in
log events and check output, and is distinct from `is_forwarded`
(which specifically means the agent *socket* is forwarded via
session-bind).

**`user_presence` is not available as a policy match field.**
It is used internally for confirmation method selection and included
in log output for forensics, but cannot be used in policy rules.

## Example policy rules

```yaml
rules:
  # Allow forwarded signing to known hosts
  - name: forwarded-known
    match:
      is_forwarded: true
      is_in_known_hosts: true
    action: allow

  # Deny forwarded signing to unknown hosts
  - name: forwarded-unknown
    match:
      is_forwarded: true
    action: deny

  # Restrict forwarded signing to specific destinations
  - name: forwarded-work
    match:
      is_forwarded: true
      ssh_dest: "git@github.com"
    action: allow
```
