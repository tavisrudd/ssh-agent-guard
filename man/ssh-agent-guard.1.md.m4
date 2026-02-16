changequote([[[,]]])dnl
define([[[MANPAGE]]],[[[1]]])dnl
% SSH-AGENT-GUARD 1 "2026-02-15" "ssh-agent-guard" "User Commands"

# NAME

ssh-agent-guard - policy-enforcing proxy for SSH agent sockets

# SYNOPSIS

**ssh-agent-guard**
[**--listen** *path*]
[**--upstream** *path*]
[**--state-dir** *path*]
[**--policy** *path*]
[**--verbose**]

**ssh-agent-guard** **--check**
[**--pid** *pid*]
[**--key** *fingerprint*]
[**--policy** *path*]

# DESCRIPTION

**ssh-agent-guard** sits between SSH clients and a real SSH agent
(typically gpg-agent), intercepting all SSH agent protocol messages.
It identifies each connecting process via SO_PEERCRED(7) and /proc,
evaluates a YAML policy to allow, deny, or require confirmation for
signing requests, and logs all operations to structured YAML files and
journald.

Key management operations (add, remove, lock, unlock) are always blocked;
the proxy is read-only by design.

For sign requests requiring confirmation, the proxy supports two methods
selected automatically based on context:

**hmac**
: YubiKey HMAC challenge-response (slot 2) when a local display is active.
The user touches the YubiKey to approve.

**remote**
: HMAC PIN entry via a tmux popup when no display is active but a YubiKey
is present.
The user presses a tmux keybinding to open the confirm prompt.

If neither method is available (no display and no YubiKey), confirmation
requests are denied with method **missing**.

# OPTIONS

### Daemon mode (default)

**--listen** *path*
: Unix socket path for the proxy to listen on.
Default: *$XDG_RUNTIME_DIR/ssh-agent-guard.sock*.

**--upstream** *path*
: Unix socket path of the real SSH agent to proxy to.
Default: *$XDG_RUNTIME_DIR/gnupg/S.gpg-agent.ssh*.

**--state-dir** *path*
: Directory for YAML event logs and status files.
Default: *~/.local/state/ssh-ag*.

**--policy** *path*
: Path to the policy configuration file.
See **ssh-agent-guard-policy**(5).
Default: *~/.config/ssh-ag/policy.yaml*.

**--verbose**
: Log all operations, including key listing requests (normally suppressed).

### Check mode

**--check**
: Gather caller context for a process and evaluate it against the policy,
printing results as YAML.
Does not start a daemon.
Useful for debugging policy rules.

**--pid** *pid*
: PID to inspect in check mode.
Default: the parent process (the shell running the command).

**--key** *fingerprint*
: Key fingerprint (*SHA256:...*) to include in policy evaluation during
check mode.

# SIGNALS

**SIGHUP**
: Reload the policy file and known_hosts.
If the new policy fails to parse, the previous policy is retained.

**SIGINT**, **SIGTERM**
: Shut down gracefully, removing the listen socket.

# CALLER IDENTIFICATION

On each connection, the proxy gathers context about the connecting
process:

**PID, UID, GID**
: From SO_PEERCRED(7), kernel-verified at connect(2) time.

**Process name, command line, working directory**
: From */proc/$pid/cmdline*, */proc/$pid/cwd*.
Nix wrapper names (*.foo-wrapped*) are unwrapped automatically.

**Environment**
: Selected variables from */proc/$pid/environ*:
**SSH_CONNECTION**, **SSH_TTY**, **DISPLAY**, **WAYLAND_DISPLAY**,
**TERM**, **TMUX_PANE**, **CLAUDECODE**.

**Ancestry**
: Process tree walked via */proc/$pid/stat* up to 8 levels.

**SSH destination**
: Extracted from the ssh command line (self or ancestors), with
flag-aware argument parsing.

**Tmux window**
: Resolved from **TMUX_PANE** via **tmux**(1) display-message.

**Remote session**
: Detected via tmux global environment, process environment, or sshd
in ancestry.

**Container**
: Detected by comparing PID namespaces between proxy and caller via
*/proc/self/ns/pid*.

**Forwarded agent**
: Detected via the **session-bind@openssh.com** agent protocol extension
(OpenSSH 8.9+), with reverse host key lookup through
*~/.ssh/known_hosts*.

# THREAT MODEL

include([[[docs/threat-model.md]]])

# SYSTEM SETUP

include([[[docs/system-setup.md]]])

# FILES

**~/.config/ssh-ag/policy.yaml**
: Policy configuration.
See **ssh-agent-guard-policy**(5).

**~/.local/state/ssh-ag/**
: Event log directory.
Each sign or mutation event produces a timestamped YAML file.

**~/.local/state/ssh-ag/current.yaml**
: Live status file consumed by status bar renderers (i3status-rs, tmux).
Contains current state (idle/confirming), pending request details, and
previous event.

**~/.local/state/ssh-ag/config_error.yaml**
: Written when the policy file fails to parse; removed on successful load.

**~/.local/state/ssh-ag/confirm/denied**
: Deny file.
Touch this file to cancel any pending confirmation.
The proxy detects it by mtime, so stale files from previous sessions
are ignored.

**~/.local/state/ssh-ag/confirm/$serial.response**
: Expected HMAC response for a specific YubiKey serial number.
Used to verify YubiKey identity during confirmation.

**~/.local/state/ssh-ag/pending/**
: Directory for PIN confirmation requests (FIFO-based).

**~/.ssh/known_hosts**
: Parsed for reverse host key fingerprint to hostname mapping, enabling
**ssh_dest** fallback and **is_in_known_hosts** policy matching on forwarded
agent sessions.
Hashed entries (**HashKnownHosts**) are skipped (irreversible by design).

# REQUIREMENTS

include([[[docs/requirements.md]]])

# YUBIKEY SETUP

include([[[docs/yubikey-setup.md]]])

# ENVIRONMENT

**SSH_AUTH_SOCK**
: Clients should set this to the proxy's listen socket to route through
the proxy.

**XDG_RUNTIME_DIR**
: Used to derive default socket paths.
Falls back to */run/user/$UID*.

**HOME**
: Used to derive default paths for state, policy, and known_hosts.

**SSH_AG_EXCLUDE_OUTPUTS**
: Comma-separated list of sway output names to ignore when detecting
an active display for confirmation method selection.
Useful for built-in LCDs that remain active but don't indicate user
presence (e.g., **DSI-1**).

# EXAMPLES

Start the proxy with default paths:

```
ssh-agent-guard
```

Start with explicit paths:

```
ssh-agent-guard \
    --listen /run/user/1000/ssh-agent-guard.sock \
    --upstream /run/user/1000/gnupg/S.gpg-agent.ssh \
    --state-dir ~/.local/state/ssh-ag \
    --policy ~/.config/ssh-ag/policy.yaml
```

Debug policy matching for the current shell:

```
ssh-agent-guard --check
```

Debug policy matching for a specific process and key:

```
ssh-agent-guard --check --pid 12345 --key SHA256:abc123
```

Reload policy after editing:

```
systemctl --user reload ssh-agent-guard
```

Cancel a pending YubiKey confirmation:

```
touch ~/.local/state/ssh-ag/confirm/denied
```

# SEE ALSO

**ssh-agent-guard-policy**(5), **ssh-agent**(1), **gpg-agent**(1), **ssh**(1)

The source repository contains additional documentation in the *docs/*
directory: caller identification internals, forwarding detection,
policy examples, threat model discussion, defense in depth, and macOS
porting analysis.
