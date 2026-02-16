# Caller identification

ssh-agent-guard identifies every process that connects to the agent
socket.  This page describes the mechanisms used and their security
properties.

## SO_PEERCRED: kernel-verified identity

When a process connects to the proxy's Unix domain socket, the kernel
records the caller's PID, UID, and GID in the socket's peer
credentials.  The proxy reads these via
[`SO_PEERCRED(7)`](https://man7.org/linux/man-pages/man7/unix.7.html)
at `accept(2)` time.

This is the only part of caller identification that is
kernel-verified.  Everything else (process name, command line,
environment) is read from `/proc` and is only as trustworthy as the
process's ability to modify its own state.

**Why SO_PEERCRED matters:** A process cannot fake its PID in peer
credentials.  The kernel populates the ucred structure at connect(2)
time, and userspace cannot override it.  This gives the proxy a
reliable anchor for the rest of its `/proc` reads.

## /proc reads

With the kernel-verified PID, the proxy reads:

| Source | Field | Notes |
|--------|-------|-------|
| `/proc/$pid/cmdline` | Command line | Null-separated, joined with spaces |
| `/proc/$pid/cwd` | Working directory | Symlink to actual path |
| `/proc/$pid/environ` | Environment | Selected variables only (see below) |
| `/proc/$pid/stat` | Parent PID | Used for ancestry walking |
| `/proc/$pid/ns/pid` | PID namespace | Compared to proxy's own namespace |

### Environment capture

Only a fixed set of environment variables are read, to limit exposure:

- `SSH_CONNECTION`, `SSH_TTY` -- session detection
- `DISPLAY`, `WAYLAND_DISPLAY` -- display detection
- `TERM`, `TMUX_PANE` -- terminal/multiplexer context
- `CLAUDECODE` -- AI tool detection

These are used for policy matching (`env:` field) and forwarded
session detection.

## Process name unwrapping

Nix wraps executables by creating a script named `.foo-wrapped` that
sets up the environment and exec's the real binary.  When the proxy
reads a process name like `.ssh-wrapped`, it strips the leading `.`
and trailing `-wrapped` to recover the original name `ssh`.

This means `process_name: ssh` matches both regular and Nix-wrapped
SSH binaries.

## Ancestry walking

The proxy walks the process tree by reading `/proc/$pid/stat` to find
the parent PID, up to 8 levels.  This produces the `local_proc_tree`
in log events and enables the `ancestor` and `parent_process_name`
policy match fields.

Ancestry is useful because the process directly connecting to the
agent socket is almost always `ssh` itself.  The interesting question
is *what launched ssh* -- was it `git push`, `rsync`, `claude`, or a
downloaded script?

Example ancestry for `git push`:

```
ssh (PID 4521)
  git (PID 4520)
    bash (PID 3001)
      tmux: server (PID 1200)
```

Here, `process_name` is `ssh`, `parent_process_name` is `git`, and
`ancestor: bash` would also match.

## SSH destination extraction

The proxy parses the SSH command line of the connecting process (or
its ancestors) to extract the destination argument.  This uses
flag-aware parsing that understands all SSH flags that consume an
argument (`-i`, `-p`, `-o`, `-J`, etc.) so it doesn't mistake a flag
value for the destination.

For forwarded agent sessions where the local ssh command line isn't
available, the destination falls back to a reverse lookup of the
session-bind host key via `~/.ssh/known_hosts`.  See
[forwarding.md](forwarding.md) for details.

## Tmux window resolution

When a caller has `TMUX_PANE` in its environment, the proxy calls
`tmux display-message -t $pane -p '#{session_name}:#{window_name}'`
to resolve the human-readable window name.  This enables the
`tmux_window` policy field, so you can write rules like:

```yaml
- name: claude-window
  match:
    tmux_window: "main:claude"
  action: confirm
```

## Container detection

The proxy compares its own PID namespace (`/proc/self/ns/pid`) with
the caller's (`/proc/$pid/ns/pid`).  If they differ, the caller is
marked `is_in_container: true`.

Container callers have incomplete identity: their `/proc` entries
may be invisible or refer to wrong PIDs unless the container shares
the host PID namespace (`--pid=host`).  Policy rules should default
to deny or confirm for container callers.

## Timing and TOCTOU

Caller identity is gathered once per connection, immediately after
`accept(2)`, before any protocol messages are processed.  The PID is
obtained via SO_PEERCRED (kernel-verified at `connect(2)` time), then
`/proc` is read for process details.  This identity is used for all
subsequent operations on that connection — it is not re-read on each
sign request.

There are two TOCTOU scenarios:

1. **exec(2) after identity capture** (common scenario): if a process
   calls `exec(2)` after the proxy has already read `/proc`, all
   subsequent sign requests use the stale (pre-exec) identity.  A
   malicious process could connect as itself, then exec into a
   different binary — but the proxy would evaluate with the original
   identity, not the new one.

2. **exec(2) between connect(2) and /proc reads** (narrow race): if
   a process calls `exec(2)` in the microseconds between `connect(2)`
   and the proxy's `/proc` reads, the proxy sees the post-exec
   identity.  A malicious process that connects, then immediately
   execs into a benign binary name, would appear as the benign
   process.  This requires precise timing and a custom binary that
   preserves the socket fd across exec.

In practice both scenarios are narrow and require a process
specifically designed to exploit them.  See the threat model for a
full discussion.
