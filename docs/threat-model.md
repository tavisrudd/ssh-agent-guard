ssh-agent-guard is designed to protect SSH signing keys on a Linux
workstation where the user runs a mix of trusted and less-trusted
software under the same Unix account.

### What it protects against

- **Unauthorized local signing** — a compromised or untrusted process
  (AI coding tool, downloaded script, browser exploit) attempts to sign
  with your SSH key.  The proxy identifies the caller and applies policy
  rules to allow, deny, or require physical confirmation.
- **Forwarded agent abuse** — a remote host you SSH into attempts to
  use your forwarded agent to sign for destinations you didn't intend.
  The proxy intercepts `session-bind@openssh.com` to detect forwarding
  and can restrict which remote destinations are permitted.
- **Key management tampering** — a process attempts to add, remove,
  lock, or unlock keys on your agent.  All mutation operations are
  unconditionally blocked.
- **Silent signing** — without the proxy, any signing operation is
  invisible.  The proxy logs every sign request with full caller context
  (process name, command line, ancestry, working directory, environment)
  to structured YAML files and journald.

### What it does NOT protect against

- **Same-user socket access** (without system hardening) — by default,
  any process running as your user can connect directly to the upstream
  agent socket, bypassing the proxy entirely.  See the system setup
  section for filesystem-level protections that close this gap.
- **Root compromise** — a root-level attacker can read any socket,
  ptrace any process, and bypass all user-level controls.
- **TOCTOU** (time-of-check-time-of-use) — caller identity is gathered
  at connect(2) time via SO_PEERCRED.  If a process calls exec(2)
  between connecting and signing, the policy evaluation uses the
  pre-exec identity.  In practice this is a narrow window (microseconds)
  and requires a process specifically designed to exploit it.
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
- **Policy enforcement** for all well-behaved software that respects
  `SSH_AUTH_SOCK` (ssh, git, rsync, and nearly all SSH clients)
- **Mutation blocking** (add/remove/lock/unlock always denied)

Most real-world threats (AI coding tools, scripts, forwarded sessions)
use `SSH_AUTH_SOCK` and will be subject to the proxy's policy.  Direct
socket access requires deliberately discovering and connecting to the
upstream path.
