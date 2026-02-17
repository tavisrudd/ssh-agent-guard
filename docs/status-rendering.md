# Status rendering

ssh-agent-guard communicates state changes to the user through an
external renderer script.  The daemon writes a YAML status file and
invokes the renderer; the renderer reads the file and updates whatever
display targets it supports (status bar, terminal title, desktop
notification, etc.).

The bundled `ssh-ag-render-status` script targets **i3status-rs** (pango
markup file) and **tmux** (user option).  You can replace it with your
own script that reads the same YAML and renders to any target.

## Interface contract

### Invocation

The daemon calls `ssh-ag-render-status` (found via `$PATH` or the
policy's `path:` search dirs) with **no arguments** and **no stdin**.
The renderer must:

1. Read `~/.local/state/ssh-ag/current.yaml`
2. Optionally read `~/.local/state/ssh-ag/config_error.yaml` (presence
   indicates a policy parse error)
3. Update its display target(s)
4. Exit promptly (the daemon may call it synchronously for confirming
   states)

The renderer is called:
- **Synchronously** when entering the `confirming` state (the user
  must see the prompt before the confirmation blocks)
- **Asynchronously** (in a goroutine) when returning to `idle` after a
  sign/mutation completes

### Replacing the renderer

Place your script on `$PATH` (or in a directory listed in the policy's
`path:` field) with the name `ssh-ag-render-status`.  The daemon
resolves it once at startup and again on each policy reload.

Alternatively, for testing, you can watch `current.yaml` with inotify
and render independently of the daemon's invocations.

## current.yaml format

Written atomically to `~/.local/state/ssh-ag/current.yaml` before
each renderer invocation.

```yaml
state: confirming          # confirming | idle | reloaded
text: "TOUCH YK: ssh: sign git@github.com"   # human-readable summary
config:                    # policy version/health
  active_version: "2026-02-15T14:30:00"
  config_sha256: "a1b2c3..."
  is_current_version: true
pending:                   # present only when state=confirming
  timestamp: "2026-02-15T14:30:22"
  trigger: sign
  process_name: ssh
  local_pid: 4521
  ssh_dest: git@github.com
  decision: confirm
  confirm_method: touch
  # ... (full logEvent fields)
previous:                  # last completed operation (any state)
  timestamp: "2026-02-15T14:29:55"
  trigger: sign
  process_name: ssh
  local_pid: 4510
  ssh_dest: git@github.com
  decision: allow
  rule: git-hosts
  # ... (full logEvent fields)
```

### States

**`confirming`**
: A sign request is waiting for user confirmation (YubiKey touch or
PIN entry).  `text` contains a human-readable summary prefixed with
`TOUCH YK:` (touch method) or `CONFIRM:` (PIN method).  `pending`
has the full event details.  This state persists until the
confirmation resolves — **no decay timer**.

**`idle`**
: A sign or mutation operation just completed.  `text` contains a
summary of what happened.  `previous` has the full event details
including the `decision` field.  The renderer should display this
briefly, then decay (the bundled script uses 2-20 seconds depending
on outcome).

**`reloaded`**
: The policy file was reloaded (via inotify or SIGHUP).  `text` is
`"config reloaded"`.  Brief display, then decay.

### Decision values (in `previous.decision`)

| Value | Meaning |
|-------|---------|
| `allow` | Policy allowed the operation |
| `deny` | Policy denied the operation |
| `confirmed` | User approved via YubiKey touch or PIN |
| `confirm-denied` | User denied, timed out, or confirm failed |

### Confirm method values (in `pending.confirm_method` or `previous.confirm_method`)

| Value | Meaning |
|-------|---------|
| `touch` | YubiKey HMAC touch (local display active) |
| `pin` | PIN entry via tmux popup (no local display) |
| `missing` | No confirmation method available (denied) |
| `rate-limited` | Too many concurrent confirms (denied) |

### logEvent fields

Both `pending` and `previous` contain the full `logEvent` structure:

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string | `2006-01-02T15:04:05` format |
| `trigger` | string | `sign`, `add`, `remove`, `remove-all`, `lock`, `unlock` |
| `process_name` | string | Caller process name (Nix wrappers unwrapped) |
| `local_pid` | int | Caller PID |
| `tmux_window` | string | e.g. `main:code` (empty if not in tmux) |
| `key_fingerprint` | string | `SHA256:...` (sign only) |
| `ssh_dest` | string | SSH destination (from cmdline or session-bind) |
| `forwarded_via` | string | Intermediate host for forwarded sessions |
| `is_forwarded` | bool | Whether session-bind indicated forwarding |
| `dest_key_fingerprint` | string | Remote host key fingerprint (session-bind) |
| `local_cwd` | string | Caller's working directory |
| `is_forwarded_session` | bool | Whether caller is in a forwarded SSH session |
| `is_container` | bool | Whether caller is in a different PID namespace |
| `decision` | string | `allow`, `deny`, `confirmed`, `confirm-denied` |
| `rule` | string | Name of the matched rule (or `default`) |
| `confirm_method` | string | `touch`, `pin`, `missing`, `rate-limited` |
| `config_sha256` | string | SHA256 of the active policy file |
| `env` | map | Selected environment variables from caller |
| `local_proc_tree` | list | Process ancestry (`pid`, `name`, `command`) |

### config_error.yaml

Written when the policy file fails to parse; removed on successful
load.  Presence of this file indicates an active config error.

```yaml
errors:
  - "line 12: unknown field foo_bar"
```

The renderer can check for this file to show a persistent error
indicator.  The bundled script shows a prominent `CFG ERR` banner
for the first 60 seconds, then decays to a persistent `CfgErr`
suffix.

## Display recommendations

### Urgency mapping

| State/decision | Urgency | Suggested behavior |
|----------------|---------|-------------------|
| `confirming` + `touch` | High | Prominent, persistent until resolved |
| `confirming` + `pin` | High | Prominent, persistent until resolved |
| `deny` / `confirm-denied` | Medium | Show for 10-20s, highlight in red |
| `allow` / `confirmed` | Low | Show briefly (2-5s), neutral color |
| `reloaded` | Low | Flash for 2-3s |
| Config error | Medium | Persistent indicator until resolved |

### Decay strategy

The bundled renderer implements decay timers (background sleep +
clear) so that idle notifications don't persist indefinitely.  Custom
renderers should implement similar decay, either with timers or by
polling `current.yaml` mtime.

Decay durations in the bundled renderer:
- `allow`: 5s
- `confirmed`: 2s (user just interacted)
- `deny`: 10s (unexpected, needs attention)
- `deny` + `method=missing`: 20s (no confirm path, needs investigation)
- `confirm-denied`: 10s
- `reloaded`: 3s
- Config error (prominent): 60s, then persistent indicator

## Examples

### Desktop notification renderer

A minimal renderer using `notify-send`:

```bash
#!/bin/bash
STATE_DIR="$HOME/.local/state/ssh-ag"
STATE=$(grep '^state:' "$STATE_DIR/current.yaml" | awk '{print $2}')
TEXT=$(grep '^text:' "$STATE_DIR/current.yaml" | sed 's/^text: *//')

case "$STATE" in
  confirming)
    notify-send -u critical "ssh-agent-guard" "$TEXT" ;;
  idle)
    DECISION=$(sed -n '/^previous:/,/^[^ ]/{ /decision:/s/.*: *//p }' \
      "$STATE_DIR/current.yaml")
    case "$DECISION" in
      deny|confirm-denied)
        notify-send -u normal "ssh-agent-guard" "$TEXT" ;;
    esac
    ;;
esac
```

### Waybar custom module

A Waybar custom module that reads `current.yaml`:

```json
"custom/ssh-agent": {
    "exec": "cat ~/.local/state/ssh-ag/i3status 2>/dev/null",
    "interval": 1,
    "format": "{}"
}
```

Or write a custom renderer that outputs JSON for Waybar's native
format (`{"text": "...", "class": "...", "tooltip": "..."}`).

### Polling-based renderer

Instead of being invoked by the daemon, watch the file directly:

```bash
#!/bin/bash
inotifywait -m -e close_write ~/.local/state/ssh-ag/current.yaml |
while read -r; do
    # parse and render
done
```

This approach works alongside (or instead of) the daemon-invoked
renderer and is useful for display targets that prefer push-based
updates.
