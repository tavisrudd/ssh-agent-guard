#!/bin/bash
# Tests for ssh-ag-render-status --test-i3status / --test-tmux
# Runs the render script against synthetic YAML inputs and checks output.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RENDER="$SCRIPT_DIR/ssh-ag-render-status"

PASS=0
FAIL=0

check() {
    local label="$1" mode="$2" input="$3" expect="$4"
    local got
    got="$(printf '%s\n' "$input" | "$RENDER" "--test-$mode")"
    if [ "$got" = "$expect" ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf 'FAIL: %s\n  expect: %s\n  got:    %s\n' "$label" "$expect" "$got"
    fi
}

# --- state: reloaded (success) ---

check "reloaded/i3" i3status \
    'state: reloaded
text: "config reloaded"' \
    '<span background="#859900" foreground="#ffffff">  config reloaded  </span>'

check "reloaded/tmux" tmux \
    'state: reloaded
text: "config reloaded"' \
    '#[bg=#859900,fg=#ffffff,bold] config reloaded #[default]'

# --- state: reloaded (with config error → reload-error) ---
# config_error.yaml check requires a real file; test the Go-driven text override
# by verifying that the render script reads text from YAML (the Go side sets TEXT
# to "CFG ERR: policy reload failed" — but the render script overrides it when
# config_error.yaml exists, which we can't test without temp dirs).
# We test the text passthrough here; the config_error.yaml logic is tested below.

# --- state: confirming ---

check "confirming/i3" i3status \
    'state: confirming
text: "TOUCH YK: [main] bash: sign example.com"' \
    '<span background="#cb4b16" foreground="#ffffff">  TOUCH YK: [main] bash: sign example.com  </span>'

check "confirming/tmux" tmux \
    'state: confirming
text: "TOUCH YK: [main] bash: sign example.com"' \
    '#[bg=#cb4b16,fg=#ffffff,bold] ▶ TOUCH YK: [main] bash: sign example.com #[default]'

# --- state: idle, allow ---

check "allow/i3" i3status \
    'state: idle
text: "bash: sign example.com"
previous:
    decision: allow
    timestamp: "2026-02-15T13:45:02"' \
    '<span background="#268bd2" foreground="#ffffff">  bash: sign example.com  </span>'

check "allow/tmux" tmux \
    'state: idle
text: "bash: sign example.com"
previous:
    decision: allow
    timestamp: "2026-02-15T13:45:02"' \
    '#[bg=#268bd2,fg=#ffffff,bold] bash: sign example.com #[default]'

# --- state: idle, confirmed ---

check "confirmed/i3" i3status \
    'state: idle
text: "[dev] ssh: sign git.example.com"
previous:
    decision: confirmed
    timestamp: "2026-02-15T14:00:01"
    confirm_method: hmac' \
    '<span background="#268bd2" foreground="#ffffff">  [dev] ssh: sign git.example.com  </span>'

# --- state: idle, deny ---

check "deny/i3" i3status \
    'state: idle
text: "curl: sign api.example.com"
previous:
    decision: deny
    timestamp: "2026-02-15T14:00:01"' \
    '<span background="#dc322f" foreground="#ffffff">  curl: sign api.example.com  </span>'

check "deny/tmux" tmux \
    'state: idle
text: "curl: sign api.example.com"
previous:
    decision: deny
    timestamp: "2026-02-15T14:00:01"' \
    '#[bg=#dc322f,fg=#ffffff,bold] curl: sign api.example.com #[default]'

# --- state: idle, confirm-denied ---

check "confirm-denied/i3" i3status \
    'state: idle
text: "ssh: CONFIRM DENIED"
previous:
    decision: confirm-denied
    timestamp: "2026-02-15T14:10:00"' \
    '<span background="#dc322f" foreground="#ffffff">  ssh: CONFIRM DENIED  </span>'

# --- state: idle, no previous decision (empty) ---

check "idle-empty/i3" i3status \
    'state: idle' \
    '(idle)'

check "idle-empty/tmux" tmux \
    'state: idle' \
    '(empty)'

# --- config_error.yaml tests (require temp dir) ---

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

# Test reload-error: reloaded state + config_error.yaml present
mkdir -p "$TMPDIR/state"
printf 'errors:\n  - "yaml: unknown field"\n' > "$TMPDIR/state/config_error.yaml"
cat > "$TMPDIR/state/current.yaml" <<'EOF'
state: reloaded
text: "config reloaded"
EOF

# Override STATE_DIR by running with modified HOME
# The script reads from $HOME/.local/state/ssh-ag/ — we need to symlink
STATE_LINK="$TMPDIR/home/.local/state/ssh-ag"
mkdir -p "$(dirname "$STATE_LINK")"
ln -s "$TMPDIR/state" "$STATE_LINK"

got="$(HOME="$TMPDIR/home" "$RENDER" --test-i3status "$TMPDIR/state/current.yaml")"
expect='<span background="#dc322f" foreground="#ffffff">  CFG ERR: policy reload failed  </span>'
if [ "$got" = "$expect" ]; then
    PASS=$((PASS + 1))
else
    FAIL=$((FAIL + 1))
    printf 'FAIL: reload-error/i3\n  expect: %s\n  got:    %s\n' "$expect" "$got"
fi

got="$(HOME="$TMPDIR/home" "$RENDER" --test-tmux "$TMPDIR/state/current.yaml")"
expect='#[bg=#dc322f,fg=#ffffff,bold] CFG ERR: policy reload failed #[default]'
if [ "$got" = "$expect" ]; then
    PASS=$((PASS + 1))
else
    FAIL=$((FAIL + 1))
    printf 'FAIL: reload-error/tmux\n  expect: %s\n  got:    %s\n' "$expect" "$got"
fi

# Test cfg-error suffix on sign event
cat > "$TMPDIR/state/current.yaml" <<'EOF'
state: idle
text: "bash: sign example.com"
previous:
    decision: allow
    timestamp: "2026-02-15T13:45:02"
EOF

got="$(HOME="$TMPDIR/home" "$RENDER" --test-i3status "$TMPDIR/state/current.yaml")"
expect='<span background="#268bd2" foreground="#ffffff">  bash: sign example.com  </span><span background="#dc322f" foreground="#ffffff"> CfgErr </span>'
if [ "$got" = "$expect" ]; then
    PASS=$((PASS + 1))
else
    FAIL=$((FAIL + 1))
    printf 'FAIL: cfg-error-suffix/i3\n  expect: %s\n  got:    %s\n' "$expect" "$got"
fi

# Test no cfg-error suffix when config_error.yaml absent
rm -f "$TMPDIR/state/config_error.yaml"

got="$(HOME="$TMPDIR/home" "$RENDER" --test-i3status "$TMPDIR/state/current.yaml")"
expect='<span background="#268bd2" foreground="#ffffff">  bash: sign example.com  </span>'
if [ "$got" = "$expect" ]; then
    PASS=$((PASS + 1))
else
    FAIL=$((FAIL + 1))
    printf 'FAIL: no-cfg-error-suffix/i3\n  expect: %s\n  got:    %s\n' "$expect" "$got"
fi

# --- Summary ---

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
