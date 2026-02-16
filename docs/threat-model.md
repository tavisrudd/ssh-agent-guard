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
