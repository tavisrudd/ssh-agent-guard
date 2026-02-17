changequote([[[,]]])dnl
define([[[MANPAGE]]],[[[1]]])dnl
% SSH-AGENT-GUARD-POLICY 5 "2026-02-16" "ssh-agent-guard" "File Formats"

# NAME

ssh-agent-guard-policy - policy configuration for ssh-agent-guard

# SYNOPSIS

*~/.config/ssh-ag/policy.yaml*

# DESCRIPTION

The policy file controls how **ssh-agent-guard**(1) handles signing
requests.  It is a YAML file with a default action, optional binary
search paths, and an ordered list of rules.  Rules are evaluated
top-to-bottom; the first matching rule wins.  If no rule matches, the
default action applies.

The policy file is watched via inotify(7) and reloaded automatically
on changes.  It can also be reloaded by sending **SIGHUP** to the proxy.
If a reload fails to parse, the previous policy is retained and the
error is written to *config_error.yaml*.

If the policy file is missing at startup, the proxy defaults to
**confirm** for all requests.

# FILE FORMAT

```yaml
default_action: allow | deny | confirm

path:
  - ~/bin
  - /usr/local/bin

confirm:
  touch:
    challenge: "deadbeef"
    slot: "2"
    timeout: "20s"
  pin:
    slot: "1"
    timeout: "120s"

rules:
  - name: rule-label
    match:
      field: value
      ...
    action: allow | deny | confirm
```

### Top-level fields

**default_action**
: Action when no rule matches.
One of **allow**, **deny**, **confirm**.
Default: **allow**.

**path**
: List of additional directories to search for external binaries
(**ykchalresp**, **ykinfo**, **tmux**, etc.).
Tilde expansion is supported.
Searched before system defaults (*/run/current-system/sw/bin*,
*/usr/bin*) and **PATH**.

**capture_extra_env_vars**
: List of additional environment variable names to read from
*/proc/$pid/environ*.  These are added to the built-in capture list
and any variables referenced in **coding_agents** env heuristics or
rule **match.env** keys.

**coding_agents**
: Map of coding agent names to detection heuristics.  Each agent
entry can specify **env** (map of env var name to expected value)
and/or **ancestors** (list of ancestor process names).  A caller is
identified as a coding agent when any heuristic matches.
Built-in agents (always active): **claude** (env CLAUDECODE=1),
**cursor** (ancestor cursor), **copilot** (ancestor copilot),
**aider** (ancestor aider), **windsurf** (ancestor windsurf),
**amp** (ancestor amp), **pi** (ancestor pi).
User entries are merged additively with builtins.

**rules**
: Ordered list of rules.
Each rule has a **match** section and an **action**.

**confirm**
: Optional section configuring YubiKey confirmation behavior.
Contains two subsections: **touch** (local HMAC confirmation) and
**pin** (remote PIN confirmation via tmux popup).
All fields have defaults; the section can be omitted entirely.

**confirm.touch.challenge**
: Hex string sent as the HMAC-SHA1 challenge to the YubiKey.
Default: **"deadbeef"**.

**confirm.touch.slot**
: YubiKey HMAC slot number for touch confirmation.
Default: **"2"**.

**confirm.touch.timeout**
: Maximum time to wait for the user to touch the YubiKey.
Go duration format (e.g., **20s**, **1m**).
Default: **20s**.

**confirm.pin.slot**
: YubiKey HMAC slot number for PIN confirmation.
The user's PIN is sent as the HMAC challenge to this slot
(no touch required).
Default: **"1"**.

**confirm.pin.timeout**
: Maximum time to wait for the user to enter a PIN via the
tmux popup.
Default: **120s**.

### Actions

**allow**
: Permit the signing request and forward it to the upstream agent.

**deny**
: Reject the signing request.
The client receives an error.

**confirm**
: Require physical confirmation before allowing.
The confirmation method is chosen automatically:
**touch** (YubiKey touch) when a local display is active,
**pin** (tmux popup PIN) when no display but YubiKey is present,
or deny with method **missing** when neither is available.

# MATCH FIELDS

All specified fields in a rule must match (AND logic).
Omitted fields are wildcards (match anything).
An empty **match** section matches everything.

### String fields

String fields support two pattern modes:

**Glob**
: Simple wildcard matching with **\*** (any characters) and **?**
(single character).
This is the default.

**Regex**
: Prefix the pattern with **~** to use Go regular expressions.
Example: **~^ssh-.\*$**.

### Available match fields

**process_name:** *name* | [*name1*, *name2*]
: Base executable name of the process connecting to the agent socket.
Usually **ssh**, since most programs (git, rsync, scp) spawn `ssh`
as a child rather than connecting to the agent directly.
Use **parent_process_name** or **ancestor** to distinguish what
launched `ssh`.
Nix wrappers are automatically unwrapped
(*.ssh-wrapped* becomes **ssh**).
Accepts a single string or a list (any match).
Exact match, not a pattern.

**parent_process_name:** *name* | [*name1*, *name2*]
: Base executable name of the immediate parent of the connecting process.
Useful for distinguishing what launched `ssh` — for example,
**git**, **bash**, or **claude** as the parent.
Accepts a single string or a list (any match).
Exact match.

**ancestor:** *name* | [*name1*, *name2*]
: Match if any process in the ancestry (up to 8 levels) has this name.
Broader than **parent_process_name** — matches grandparents and above.
Accepts a single string or a list.
Exact match.

**command:** *pattern*
: Glob or regex against the caller's full command line.

**ssh_dest:** *pattern*
: Match against the SSH destination hostname or *user@host*.
Resolved from the caller's command line when available, falling back
to the hostname from **session-bind@openssh.com** (via *known_hosts*
reverse lookup).
Patterns **without @** match the hostname only — the *user@* prefix
is stripped before matching.  "github.com" matches both "github.com"
and "git@github.com".
Patterns **with @** match the full *user@host* string.
"git@github.com" matches only "git@github.com", not "deploy@github.com".
Place specific *user@host* rules before broader hostname rules to
avoid shadowing.

**is_in_known_hosts:** *true* | *false*
: Boolean.
Matches only if the session-bind destination host key
was found in known_hosts.

**forwarded_via:** *pattern*
: Glob or regex against the intermediate host in *user@host* format,
extracted from SSH ControlMaster multiplexing.
Parsed from the mux process command line
(*ssh: /path/host_port_user [mux]*).

**is_forwarded:** *true* | *false*
: Boolean.
Whether the agent connection is forwarded (from a remote SSH session)
as reported by the **session-bind@openssh.com** extension.

**key:** *prefix*
: Prefix match against the key fingerprint (*SHA256:...*).
Allows matching specific keys without specifying the full fingerprint.

**cwd:** *pattern*
: Glob or regex against the caller's working directory.

**cgroup:** *pattern*
: Glob or regex against the caller's cgroup path (from
*/proc/$pid/cgroup*).  On cgroup v2, this is the path after *0::*
(e.g., */user.slice/user-1000.slice/session-1.scope*).  On cgroup v1,
the full first hierarchy line is returned including controller prefix
(e.g., *10:devices:/docker/abc123*).  Patterns like *\*docker\** match
either format.

**tmux_window:** *pattern*
: Glob or regex against the tmux session:window name (*main:claude*).
Resolved from **TMUX_PANE** in the caller's environment.

**is_in_container:** *true* | *false*
: Boolean.
Whether the caller's PID namespace differs from the proxy's.  When
true, the proxy cannot fully trust */proc/$pid* reads — the caller's
process name, command line, and ancestry may be unavailable or refer
to wrong processes.  This is specifically a PID namespace check; other
namespace mismatches (mnt, net, user, uts, cgroup) are recorded in
**namespace_mismatches** for forensics but do not affect this field.
Containers share the host PID namespace with **--pid=host**.

**is_coding_agent:** *true* | *false*
: Boolean.
Whether the caller was identified as a coding agent by the
**coding_agents** heuristics.  The detected agent name is available
in log events as **coding_agent_name**.

**env:** *map*
: Map of environment variable names to expected values.
All specified variables must match.
The capture list includes built-in variables (**SSH_CONNECTION**,
**SSH_TTY**, **DISPLAY**, **WAYLAND_DISPLAY**, **TERM**,
**TMUX_PANE**, **CLAUDECODE**) plus any from **capture_extra_env_vars**,
**coding_agents** env keys, and other rules' **match.env** keys.
Variables referenced in rules are automatically captured.

# EXAMPLES

### Default-deny with explicit allow rules

```yaml
default_action: deny

path:
  - ~/bin

rules:
  # Git operations to known hosts
  - name: git-hosts
    match:
      ssh_dest: "git@github.com"
    action: allow

  # Direct SSH to known hosts
  - name: direct-known
    match:
      is_in_known_hosts: true
    action: allow

  # Forwarded agent to known hosts
  - name: forwarded-known
    match:
      is_forwarded: true
      is_in_known_hosts: true
    action: allow

  # Forwarded to unknown hosts
  - name: forwarded-unknown
    match:
      is_forwarded: true
    action: deny
```

### Confirm for coding agents

```yaml
default_action: allow

coding_agents:
  aider:
    ancestors: [aider]

rules:
  # Require confirmation for any detected coding agent
  - name: coding-agent-confirm
    match:
      is_coding_agent: true
    action: confirm
```

### Deny all container access

```yaml
default_action: allow

rules:
  - name: container-deny
    match:
      is_in_container: true
    action: deny
```

### Restrict by working directory

```yaml
default_action: confirm

rules:
  - name: git-from-src
    match:
      cwd: "/home/alice/src/*"
      parent_process_name: [git, git-remote-https]
    action: allow
```

### Regex matching

```yaml
default_action: deny

rules:
  - name: local-hosts
    match:
      command: "~ssh.*\\.local"
    action: allow
```

# RULE EVALUATION

1. Rules are evaluated in order; the first match wins.
2. All fields in a rule's **match** section must match (AND logic).
3. Omitted fields match anything (wildcard).
4. An empty **match** section matches all requests.
5. If no rule matches, the **default_action** applies.

Use **ssh-agent-guard --check** to debug rule evaluation.
It shows which rules matched, which didn't, and why.

# POLICY RELOAD

The policy file is monitored for changes via inotify(7) (watching the
containing directory to handle symlink replacements and atomic renames).

On successful reload, the new rules take effect immediately for all
subsequent signing requests.  Active connections are not interrupted.

On failed reload (YAML parse error), the previous policy is retained.
The error is logged to journald, written to *config_error.yaml*, and
surfaced in the status bar.

# MISSING POLICY FILE

If the policy file does not exist, the proxy defaults to **confirm**
for all requests.  This is a safe default: all signing requires physical
confirmation.  No error is recorded (the missing file is an expected
state during initial setup).

# SEE ALSO

**ssh-agent-guard**(1), **yaml**(1), **glob**(7)

The source repository contains a detailed policy guide with worked
examples in *docs/policy-guide.md*.
