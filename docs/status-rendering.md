# Status rendering

ssh-agent-guard communicates state changes to the user through an
external renderer script.  The daemon writes a YAML status file and
invokes the renderer; the renderer reads the file and updates whatever
display targets it supports (status bar, terminal title, desktop
notification, etc.).

The bundled `ssh-ag-render-status` script targets **i3status-rs** (pango
markup file) and **tmux** (user option).  You can customize rendering
at two levels: override just the render functions (keeping the bundled
lifecycle/decay logic), or replace the entire script.

## Bundled renderer setup

### tmux

The renderer sets a global user option `@ssh_ag_status` on each event.
Reference it in your status line:

```
# ~/.tmux.conf
set -g status-right '#{@ssh_ag_status} %H:%M'
```

The option contains tmux format strings (`#[bg=...,fg=...,bold]`)
that render as colored badges.  When idle, the option is empty.

No polling or interval is needed — the renderer calls
`tmux set -g @ssh_ag_status` and `tmux refresh-client -S` directly,
so updates appear instantly.

### i3status-rs

The renderer writes pango markup to `~/.local/state/ssh-ag/i3status`.
Use a `custom` block with `file` format:

```toml
# ~/.config/i3status-rust/config.toml
[[block]]
block = "custom"
format = " $text "
[block.format]
full = " {file:~/.local/state/ssh-ag/i3status} "
```

i3status-rs watches the file via inotify and updates when it changes.
The file contains raw pango `<span>` markup with background/foreground
colors.  When idle, the file is empty (block hidden).

### Waybar

Waybar can read the same i3status file, or you can write a custom
renderer that outputs Waybar's native JSON:

```json
"custom/ssh-agent": {
    "exec": "cat ~/.local/state/ssh-ag/i3status 2>/dev/null",
    "interval": 1,
    "format": "{}"
}
```

## Customizing the renderer

The bundled script has three concerns:

1. **Parsing** — reads `current.yaml`, extracts fields
2. **Classification** — maps state + decision to event type, color,
   decay duration
3. **Rendering** — updates display targets (i3status file, tmux option)

The rendering is factored into three overridable functions.  The
parsing, classification, and decay timer management are handled by
the core script and don't need to be reimplemented.

### Override file

Create `~/.config/ssh-ag/render.sh` (or `$XDG_CONFIG_HOME/ssh-ag/render.sh`)
to override any of the three render functions.  The file is sourced
by the bundled script after the defaults are defined, so you only
need to redefine the functions you want to change.

### render_notify

Called when there's an active notification to display.

Available variables:

| Variable    | Description                                     |
|-------------|-------------------------------------------------|
| `EV_TYPE`   | Event type (see "States" and "Decision values") |
| `COLOR`     | Hex color for the event (solarized palette)     |
| `TEXT`      | Human-readable summary string                   |
| `CFG_ERROR` | `"true"` if `config_error.yaml` exists          |

Also available: `STATE_DIR`, `I3STATUS` (paths for file output).

### render_decay

Called when an active notification expires (via background sleep timer).
Transitions to a residual display.

| Variable       | Description                                         |
|----------------|-----------------------------------------------------|
| `DECAY_TIME`   | `"HH:MM"` from the previous event, or empty         |
| `DECAY_DENIED` | `"true"` if the previous event was a denial         |
| `CFG_ERROR`    | `"true"` if `config_error.yaml` exists (re-checked) |

### render_clear

Called to clear all display (or show a persistent config error indicator).

| Variable    | Description                            |
|-------------|----------------------------------------|
| `CFG_ERROR` | `"true"` if `config_error.yaml` exists |

### Example: desktop notifications

Add `notify-send` alongside the default i3status/tmux rendering:

```bash
# ~/.config/ssh-ag/render.sh
# Extend the default — call the original, then add notifications.
# Save the original function before redefining.
eval "$(declare -f render_notify | sed 's/render_notify/orig_render_notify/')"

render_notify() {
    orig_render_notify  # keep i3status + tmux working

    case "$EV_TYPE" in
        confirming)
            notify-send -u critical -t 0 "ssh-agent-guard" "$TEXT" ;;
        deny|confirm-denied)
            notify-send -u normal "ssh-agent-guard" "$TEXT" ;;
    esac
}
```

### Example: replace tmux with terminal title

```bash
# ~/.config/ssh-ag/render.sh
render_notify() {
    if [ -n "$TEXT" ]; then
        printf '\033]0;SSH: %s\007' "$TEXT"
    fi
    # still write i3status file
    printf '<span background="%s" foreground="#ffffff">  %s  </span>' \
        "$COLOR" "$TEXT" > "$I3STATUS"
}

render_decay() {
    printf '\033]0;\007'  # clear title
    : > "$I3STATUS"
}

render_clear() {
    printf '\033]0;\007'
    : > "$I3STATUS"
}
```

### Example: only tmux, no i3status

```bash
# ~/.config/ssh-ag/render.sh
render_notify() {
    local prefix=""
    case "$EV_TYPE" in confirming) prefix=" ▶" ;; esac
    tmux set -g @ssh_ag_status \
        "#[bg=$COLOR,fg=#ffffff,bold]${prefix} $TEXT #[default]" \
        2>/dev/null || true
    tmux refresh-client -S 2>/dev/null || true
}

render_decay() {
    tmux set -g @ssh_ag_status "" 2>/dev/null || true
    tmux refresh-client -S 2>/dev/null || true
}

render_clear() {
    tmux set -g @ssh_ag_status "" 2>/dev/null || true
    tmux refresh-client -S 2>/dev/null || true
}
```

## Replacing the script entirely

If the override mechanism isn't sufficient, replace
`ssh-ag-render-status` entirely.  Place your script on `$PATH` (or
in a directory listed in the policy's `path:` field) with the same
name.  The daemon resolves it at startup and on each policy reload.

Your script must:

1. Read `~/.local/state/ssh-ag/current.yaml`
2. Optionally read `~/.local/state/ssh-ag/config_error.yaml`
3. Update its display target(s)
4. Exit promptly (called synchronously for `confirming` states)

You are responsible for decay timers and lifecycle management.

Alternatively, ignore the daemon's invocations entirely and watch
`current.yaml` with inotify:

```bash
inotifywait -m -e close_write ~/.local/state/ssh-ag/current.yaml |
while read -r; do
    # parse and render
done
```

## Interface contract

### Invocation

The daemon calls `ssh-ag-render-status` with **no arguments** and
**no stdin**.

The renderer is called:
- **Synchronously** when entering the `confirming` state (the user
  must see the prompt before the confirmation blocks)
- **Asynchronously** (in a goroutine) when returning to `idle`

### Decay timers

The bundled script manages decay via background subshells that sleep
and re-render.  Each new invocation kills previous decay timers
(tracked via PID files in the state directory).

Decay durations:
- `allow`: 5s
- `confirmed`: 2s (user just interacted)
- `deny`: 10s (unexpected, needs attention)
- `deny` + `method=missing`: 20s (no confirm path)
- `confirm-denied`: 10s
- `reloaded`: 3s
- `reload-error`: 60s
- Config error (prominent): 60s, then persistent indicator
- `confirming`: no decay (persists until resolved)

## current.yaml reference

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
: Sign request waiting for user confirmation.  `text` is prefixed
with `TOUCH YK:` (touch) or `CONFIRM:` (PIN).  `pending` has full
event details.  Persists until resolved.

**`idle`**
: Operation just completed.  `previous` has full event details.

**`reloaded`**
: Policy file reloaded via inotify or SIGHUP.

### Decision values

| Value            | Meaning                                   |
|------------------|-------------------------------------------|
| `allow`          | Policy allowed the operation              |
| `deny`           | Policy denied the operation               |
| `confirmed`      | User approved via YubiKey touch or PIN    |
| `confirm-denied` | User denied, timed out, or confirm failed |

### Confirm method values

| Value          | Meaning                                     |
|----------------|---------------------------------------------|
| `touch`        | YubiKey HMAC touch (local display active)   |
| `pin`          | PIN entry via tmux popup (no local display) |
| `missing`      | No confirmation method available (denied)   |
| `rate-limited` | Too many concurrent confirms (denied)       |

### logEvent fields

Both `pending` and `previous` contain the full `logEvent` structure:

| Field                  | Type   | Description                                             |
|------------------------|--------|---------------------------------------------------------|
| `timestamp`            | string | `2006-01-02T15:04:05` format                            |
| `trigger`              | string | `sign`, `add`, `remove`, `remove-all`, `lock`, `unlock` |
| `process_name`         | string | Caller process name (Nix wrappers unwrapped)            |
| `local_pid`            | int    | Caller PID                                              |
| `tmux_window`          | string | e.g. `main:code` (empty if not in tmux)                 |
| `key_fingerprint`      | string | `SHA256:...` (sign only)                                |
| `ssh_dest`             | string | SSH destination (from cmdline or session-bind)          |
| `forwarded_via`        | string | Intermediate host for forwarded sessions                |
| `is_forwarded`         | bool   | Whether session-bind indicated forwarding               |
| `dest_key_fingerprint` | string | Remote host key fingerprint (session-bind)              |
| `local_cwd`            | string | Caller's working directory                              |
| `is_forwarded_session` | bool   | Whether caller is in a forwarded SSH session            |
| `is_container`         | bool   | Whether caller is in a different PID namespace          |
| `decision`             | string | `allow`, `deny`, `confirmed`, `confirm-denied`          |
| `rule`                 | string | Name of the matched rule (or `default`)                 |
| `confirm_method`       | string | `touch`, `pin`, `missing`, `rate-limited`               |
| `config_sha256`        | string | SHA256 of the active policy file                        |
| `env`                  | map    | Selected environment variables from caller              |
| `local_proc_tree`      | list   | Process ancestry (`pid`, `name`, `command`)             |

### config_error.yaml

Written when the policy file fails to parse; removed on successful
load.

```yaml
errors:
  - "line 12: unknown field foo_bar"
```
