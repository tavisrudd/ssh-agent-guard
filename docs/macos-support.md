# macOS support

ssh-agent-guard is Linux-only.  This document evaluates what a macOS
port would look like: what works, what needs new code, what's degraded,
and how the upstream socket protection story differs.

## Architecture recap

The guard has two security layers:

1. **Policy proxy** — intercepts the SSH agent protocol, identifies
   callers, applies YAML rules, logs events.
2. **Socket isolation** — the upstream (real) agent socket is made
   inaccessible to normal processes so they can only reach the proxy.

Without socket isolation, any same-user process that discovers the
upstream path can connect directly, bypassing the guard entirely.

## What already works (pure Go, no OS dependencies)

These components are portable today with no changes:

- SSH agent protocol proxy (`proxy.go`) — pure `golang.org/x/crypto/ssh/agent`
- Policy engine (`policy.go`) — YAML rules, glob/regex matching
- Policy file watching — fsnotify uses kqueue on macOS, already cross-platform
- Session-bind parsing (`session.go`) — SSH wire format
- Known-hosts reverse lookup (`session.go`) — pure string/crypto
- YAML event logging (`logger.go`) — file I/O
- FIFO-based PIN confirmation (`confirm_pin.go`) — `unix.Mkfifo` is POSIX
- YubiKey HMAC confirmation (`confirm.go`) — shells out to
  `ykchalresp`/`ykinfo`, available via Homebrew
- Signal handling — SIGHUP/SIGINT/SIGTERM are POSIX
- Mutation blocking — unconditional deny of add/remove/lock/unlock
- SSH destination extraction — command-line parsing, pure Go
- SSH mux host parsing — pure string manipulation

## Caller identification on macOS

This is the critical question.  On Linux, caller identification uses
`SO_PEERCRED` (kernel-verified PID/UID/GID) and `/proc` reads.  macOS
has different but largely equivalent mechanisms.

### Peer credentials

| Data    | Linux                           | macOS                                     |
|---------|---------------------------------|-------------------------------------------|
| PID     | `SO_PEERCRED` → `ucred.Pid`     | `LOCAL_PEERPID` via `GetsockoptInt()`     |
| UID/GID | `SO_PEERCRED` → `ucred.Uid/Gid` | `LOCAL_PEERCRED` via `GetsockoptXucred()` |

Both are populated by the kernel at `connect(2)` time and cannot be
forged by userspace.

`LOCAL_PEERPID` is undocumented but present in XNU headers, used by
launchd internally, and stable since at least macOS 10.8.  Go's
`golang.org/x/sys/unix` supports it via `GetsockoptInt(fd, unix.SOL_LOCAL,
unix.LOCAL_PEERPID)` (added 2021).  `GetsockoptXucred` is documented
and stable.

### Process inspection

| Data              | Linux                     | macOS                                    |
|-------------------|---------------------------|------------------------------------------|
| Executable path   | `/proc/$pid/exe` readlink | `proc_pidpath()` (libproc)               |
| Command line      | `/proc/$pid/cmdline`      | `sysctl KERN_PROCARGS2`                  |
| Environment       | `/proc/$pid/environ`      | `sysctl KERN_PROCARGS2` (env after argv) |
| Working directory | `/proc/$pid/cwd` readlink | `proc_pidinfo(PROC_PIDVNODEPATHINFO)`    |
| Parent PID        | `/proc/$pid/stat` field 4 | `sysctl KERN_PROC` → `kinfo_proc`        |

All macOS APIs work for same-user processes without root.
`KERN_PROCARGS2` returns the full user stack region (exec path + argv +
envp, null-separated); the XNU kernel checks UID match and allows
same-user access.  This means env-based policy rules (`CLAUDECODE`,
`TMUX_PANE`, `SSH_CONNECTION`, etc.) work on macOS.

`proc_pidpath()` and `proc_pidinfo()` require cgo or a syscall wrapper.

### What's missing

- **PID namespace detection** — macOS has no PID namespaces.  The
  `is_in_container` field would always be false.  Not relevant since
  macOS doesn't have native containers (Docker Desktop runs a Linux VM).
- **Nix wrapper unwrapping** — the `.foo-wrapped` naming convention is
  NixOS-specific.  On macOS with nix-darwin the wrapping may differ, but
  the stripping logic is harmless when there's nothing to strip.

### The LOCAL_PEERPID risk

`LOCAL_PEERPID` is the foundation of the macOS port.  If Apple removes
it, caller identification breaks entirely — the port degrades to a dumb
proxy with session-bind detection and logging but no caller-aware
policy.  On Linux, `SO_PEERCRED` is a documented, stable kernel ABI.
This is the single biggest portability risk.

## Environment adaptation

These need new platform-specific code but are straightforward:

| Component      | Linux                                  | macOS                                 |
|----------------|----------------------------------------|---------------------------------------|
| Runtime dir    | `$XDG_RUNTIME_DIR` or `/run/user/$UID` | `$TMPDIR` (per-user, launchd-managed) |
| Binary paths   | `/run/current-system/sw/bin`           | `/opt/homebrew/bin`, `/usr/local/bin` |
| Lock detection | `swaymsg` + `swaylock` check           | `CGSessionCopyCurrentDictionary`      |
| Service mgmt   | systemd user unit                      | launchd plist                         |
| Status bar     | i3status-rs pango + tmux               | tmux only (no i3status-rs)            |
| `stat` command | GNU `stat -c %Y`                       | BSD `stat -f %m`                      |
| Build targets  | `x86_64-linux`, `aarch64-linux`        | + `x86_64-darwin`, `aarch64-darwin`   |

## Implementation approach

The cleanest path:

1. **Split `caller.go` into platform files** — `caller_linux.go` with
   `//go:build linux` (current code, unchanged) and `caller_darwin.go`
   implementing `getPeerCred()` via `LOCAL_PEERPID` + `LOCAL_PEERCRED`,
   process inspection via sysctl/libproc, and a no-op for PID namespace
   detection.

2. **Split `confirm.go` display detection** — extract
   `hasActiveDisplay()` behind a platform interface.  macOS
   implementation checks screen lock state via CoreGraphics or IOKit.

3. **Platform runtime dir** — `_darwin.go` returning `os.TempDir()` or
   `$TMPDIR`.

4. **Everything else unchanged** — proxy, policy, logging, session-bind,
   FIFO IPC, YubiKey confirmation all work as-is.

## Feature matrix

| Feature                             | Linux               | macOS                               |
|-------------------------------------|---------------------|-------------------------------------|
| Agent protocol proxy                | yes                 | yes                                 |
| Policy engine                       | yes                 | yes                                 |
| Session-bind / forwarding detection | yes                 | yes (macOS ships OpenSSH 9.x)       |
| Known-hosts reverse lookup          | yes                 | yes                                 |
| Caller PID (kernel-verified)        | yes (`SO_PEERCRED`) | yes (`LOCAL_PEERPID`, undocumented) |
| Caller UID/GID                      | yes                 | yes (`LOCAL_PEERCRED`)              |
| Process name, cmdline               | yes (`/proc`)       | yes (`KERN_PROCARGS2`)              |
| Environment vars                    | yes (`/proc`)       | yes (`KERN_PROCARGS2`)              |
| Working directory                   | yes (`/proc`)       | yes (`proc_pidinfo`)                |
| Ancestry walking                    | yes (`/proc`)       | yes (`sysctl KERN_PROC`)            |
| Container detection                 | yes (PID namespace) | n/a                                 |
| YubiKey confirmation                | yes                 | yes (Homebrew)                      |
| Display lock detection              | yes (sway)          | needs rewrite                       |
| Logging                             | yes                 | yes                                 |
| fsnotify policy reload              | yes (inotify)       | yes (kqueue)                        |
| Mutation blocking                   | yes                 | yes                                 |

## Upstream socket protection

### The problem (both platforms)

Any same-user process that knows the upstream socket path can connect
directly, bypassing the guard.  The `system-setup.md` approach (0700
directory) prevents *other users* from reaching the socket, but
same-user processes can traverse their own directories.  The practical
defense is that most processes use `SSH_AUTH_SOCK` and don't know the
upstream path.

A determined attacker running as the same user can discover the
upstream path trivially: `ps` output shows the guard's `--upstream`
argument on both platforms.

### Linux socket protection

Linux has multiple mechanisms to restrict same-user access to the
upstream socket, none of which require a separate user:

- **Landlock** (Linux 5.13+) — unprivileged LSM that lets a process
  restrict its own filesystem access.  An untrusted process (or its
  launcher) can drop access to the upstream socket directory before
  executing.  No root, no policy files, just syscalls.
- **AppArmor / SELinux** — MAC policies can restrict which executables
  or confined domains can access specific paths.  Commonly available on
  Ubuntu (AppArmor) and Fedora/RHEL (SELinux).
- **systemd sandboxing** — `InaccessiblePaths=` in a user service unit
  makes paths invisible to that service.  Useful for sandboxing
  AI tools or other untrusted daemons.
- **Mount namespaces** — `unshare -m` creates a private mount namespace
  where the upstream socket directory can be bind-mounted over or
  unmounted entirely.  The guard runs in the init namespace with access;
  untrusted processes run in a restricted namespace.
- **seccomp-bpf** — can filter `connect(2)` syscalls, though this is
  coarse-grained for socket path restriction.

These range from lightweight (Landlock, systemd directives) to
comprehensive (SELinux, mount namespaces).  The 0700 directory is the
simplest baseline; the above provide actual per-process enforcement.

### macOS socket protection

macOS has fewer options, and the strongest one is deprecated:

- **0700 directory** — same baseline as Linux.  Prevents other users,
  not same-user.
- **sandbox-exec** (deprecated since macOS 10.15, still functional) —
  seatbelt profiles can deny per-process access to specific paths:
  ```scheme
  (version 1)
  (allow default)
  (deny file-read* file-write*
    (subpath "/Users/tavis/Library/ssh-agent-upstream"))
  ```
  This is kernel-enforced per-process restriction, similar in effect
  to AppArmor.  But the API is deprecated with no announced removal
  date, and wrapping every untrusted process is operationally awkward.
- **App Sandbox** — apps distributed via the Mac App Store are
  sandboxed and generally can't reach arbitrary sockets.  But developer
  CLI tools (node, python, AI agents) are not sandboxed.
- **Endpoint Security framework** — a signed, notarized system
  extension can intercept file operations and enforce arbitrary policy.
  This is how commercial EDR products work.  Massively overweight for
  this use case.
- **Separate user for the agent** — if the upstream agent runs as a
  dedicated user (e.g., `_sshagent`), same-user processes genuinely
  cannot reach the socket.  The guard bridges the gap via group
  membership.  This is the only approach that provides actual same-user
  isolation, but it's complex.  (This also works on Linux but is
  equally complex there.)
- **Keychain integration** (complementary) — macOS's built-in ssh-agent
  can prompt via Keychain on every key use.  No caller identification,
  no per-destination policy, but provides a second confirmation layer
  independent of the guard.

The gap vs Linux: macOS has no equivalent to Landlock, mount namespaces,
or systemd `InaccessiblePaths=`.  The only kernel-enforced per-process
file restriction (`sandbox-exec`) is deprecated.  Practically, a macOS
deployment relies more heavily on the obscurity of the upstream socket
path and the fact that well-behaved software uses `SSH_AUTH_SOCK`.

### Upstream socket discovery

On both platforms, a same-user attacker can discover the upstream path:

| Method       | Linux                                    | macOS                                 |
|--------------|------------------------------------------|---------------------------------------|
| Process args | `/proc/$(pidof ssh-agent-guard)/cmdline` | `ps -eo args \| grep ssh-agent-guard` |
| Open FDs     | `/proc/$pid/fd/`                         | `lsof -p $pid`                        |
| FS search    | `find $XDG_RUNTIME_DIR -name 'S.gpg-*'`  | `find $TMPDIR -name '*.sock'`         |

The 0700 directory doesn't prevent discovery — it prevents *traversal*
by other UIDs.  A same-user process that discovers the path can connect
to it directly.

## Threat model differences

| Threat               | Linux                  | macOS                | Notes                |
|----------------------|------------------------|----------------------|----------------------|
| Uses SSH_AUTH_SOCK   | Guard applies policy   | Same                 | Primary use case     |
| Bypass to upstream   | Preventable (Landlock) | Hard (sandbox depr.) | **Main gap**         |
| Forwarding abuse     | Session-bind detection | Same                 | Protocol-level       |
| AI tool injection    | Policy + confirmation  | Same                 | `CLAUDECODE` on both |
| Container bind-mount | Detectable (PID ns)    | N/A                  | Docker uses Linux VM |
| Root compromise      | Bypasses all           | Same                 | Out of scope         |
| PID recycling        | Narrow window          | Same                 | macOS PIDs 32-bit    |

## Summary

A macOS port is feasible and would retain most of the guard's value.
Caller identification is nearly as strong as Linux — the main weakness
is `LOCAL_PEERPID` being undocumented.  The proxy, policy engine,
session-bind detection, logging, and YubiKey confirmation all work
unmodified.

The significant gap is upstream socket protection.  Linux offers
multiple kernel-enforced mechanisms (Landlock, namespaces, MAC) to
prevent same-user bypass without complexity.  macOS has no good
equivalent — `sandbox-exec` is the closest but is deprecated.  A macOS
deployment must rely more on the guard being the only advertised path
(`SSH_AUTH_SOCK`) and on the upstream socket path not being widely
known.  For most real-world threats (AI tools, scripts, forwarded
sessions), this is sufficient — these use `SSH_AUTH_SOCK` and don't
hunt for the upstream socket.
