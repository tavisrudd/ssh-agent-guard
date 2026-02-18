# Policy guide

This guide walks through common policy configurations for
ssh-agent-guard.  For the complete reference of match fields and
syntax, see **ssh-agent-guard-policy(5)**.

## How rules work

Rules are evaluated top-to-bottom; the first matching rule wins.
All fields in a rule's `match` section must match (AND logic).
Omitted fields match anything.  If no rule matches, `default_action`
applies.

Place specific rules before general ones.  A common pattern is to
allow known-good operations first, then restrict or deny everything
else.

## Default-deny vs default-allow

### Default-deny (recommended for high-security setups)

```yaml
default_action: deny

rules:
  - name: git-hosts
    match:
      ssh_dest: "git@github.com"
    action: allow

  - name: direct-known
    match:
      is_in_known_hosts: true
    action: allow
```

Every signing operation is denied unless a rule explicitly allows it.
Start here if you want maximum control and are willing to add rules
as you discover new legitimate uses.  Use `check` and log files to
find operations that need rules.

### Default-allow (recommended for getting started)

```yaml
default_action: allow

rules:
  - name: coding-agents
    match:
      is_coding_agent: true
    action: confirm

  - name: container-deny
    match:
      is_in_container: true
    action: deny
```

Everything is allowed by default; rules add restrictions for specific
cases.  Start here for visibility and logging without disrupting your
workflow, then tighten as you learn your signing patterns.

### Default-confirm (lock everything down)

```yaml
default_action: confirm
```

Every signing operation requires physical YubiKey confirmation unless
a rule says otherwise.  Use this if you have a YubiKey and want to
approve every operation individually.

## Understanding ssh_dest

The `ssh_dest` value comes from two sources:

- **Command line parsing** (direct SSH): includes the user if
  specified — `git@github.com`, `user@host`, or just `host`.
- **session-bind + known_hosts** (forwarded sessions): bare
  hostname only — `github.com`, `myserver.example.com`.

**Patterns without `@` match against the hostname only** — the
`user@` prefix is stripped from the value before matching.  This
means `github.com` matches both `github.com` (session-bind) and
`git@github.com` (command line).

**Patterns containing `@` match the full value** — including the
user portion.  `git@github.com` matches only `git@github.com`, not
`deploy@github.com` or bare `github.com`.

| Pattern          | `git@github.com` | `deploy@github.com` | `github.com` |
|------------------|------------------|---------------------|--------------|
| `github.com`     | yes (hostname)   | yes (hostname)      | yes          |
| `git@github.com` | yes              | no                  | no           |
| `*.example.com`  | —                | —                   | —            |
| `git@*`          | yes              | no                  | no           |
| `*@github.com`   | yes              | yes                 | no           |

**Rule ordering for mixed specificity:** Place specific `user@host`
rules before broader hostname rules.  First match wins:

```yaml
rules:
  # Specific: allow git@ without confirmation
  - name: git-github
    match:
      ssh_dest: "git@github.com"
    action: allow

  # Broad: confirm all other users at github.com
  - name: all-github
    match:
      ssh_dest: "github.com"
    action: confirm
```

With this policy, `git@github.com` matches the first rule (allow),
while `deploy@github.com` skips it (wrong user) and matches the
second rule (confirm).

## Common scenarios

### Git hosting

Allow signing for well-known git hosts without confirmation:

```yaml
  # Exact user@host — matches direct `ssh git@github.com` only
  - name: git-hosts
    match:
      ssh_dest: "git@github.com"
    action: allow

  # Multiple hosts, specific user
  - name: git-hosts-all
    match:
      ssh_dest: "~^git@(github\\.com|gitlab\\.com|codeberg\\.org)$"
    action: allow

  # Any user at github.com, including forwarded sessions (bare hostname)
  - name: github-any
    match:
      ssh_dest: "*github.com"
    action: allow
```

### Coding agents

AI coding tools that make SSH connections (git push, remote
operations) can be required to confirm via YubiKey.  The proxy
detects coding agents automatically via env vars and ancestor
process names.

**Simple: match any coding agent**

```yaml
  - name: coding-agents
    match:
      is_coding_agent: true
    action: confirm
```

Built-in detection covers Claude (`CLAUDECODE=1`), Cursor
(ancestor `cursor`), Copilot (ancestor `copilot`), Aider
(ancestor `aider`), Windsurf (ancestor `windsurf`), Amp
(ancestor `amp`), and Pi (ancestor `pi`).

**Extend with additional agents**

Add new agents or extend built-in ones via the top-level
`coding_agents` section:

```yaml
coding_agents:
  aider:
    ancestors: [aider]
  windsurf:
    env:
      WINDSURF_ID: "1"
    ancestors: [windsurf]

rules:
  - name: coding-agents
    match:
      is_coding_agent: true
    action: confirm
```

The detected agent name appears in log events as
`coding_agent_name` (e.g., `"claude"`, `"cursor"`, `"aider"`).

**Specific agent via env (still works)**

```yaml
  - name: claude-only
    match:
      env:
        CLAUDECODE: "1"
    action: confirm
```

Env vars referenced in `match.env` are automatically captured
from `/proc/pid/environ` — no need to list them separately.

### Forwarded agent restrictions

When you SSH to a remote host with `-A`, restrict what it can sign:

```yaml
  # Forwarded to known hosts — allow
  - name: forwarded-known
    match:
      is_forwarded: true
      is_in_known_hosts: true
    action: allow

  # Forwarded to unknown — deny
  - name: forwarded-unknown
    match:
      is_forwarded: true
    action: deny
```

For tighter control, restrict forwarded signing to specific
destinations:

```yaml
  - name: forwarded-github-only
    match:
      is_forwarded: true
      ssh_dest: "git@github.com"
    action: allow

  - name: forwarded-deny-rest
    match:
      is_forwarded: true
    action: deny
```

### Container policies

`is_in_container` is true when the caller's PID namespace differs
from the proxy's.  This matters because the proxy identifies callers
via `/proc/$pid` — when PID namespaces differ, those reads may
return empty or wrong data, making the caller's identity (name,
command, ancestry) untrustworthy.  Default to deny:

```yaml
  - name: container-deny
    match:
      is_in_container: true
    action: deny
```

### Restrict by working directory

Allow git operations only from your source directory:

```yaml
  - name: git-from-src
    match:
      cwd: "/home/*/src/*"
      parent_process_name: [git, git-remote-https]
    action: allow
```

### Restrict by tmux window

If you use named tmux windows for different tasks:

```yaml
  - name: deploy-window
    match:
      tmux_window: "main:deploy"
    action: allow

  - name: untrusted-window
    match:
      tmux_window: "main:scratch"
    action: deny
```

### Team shared hosts

On a shared host where multiple users might forward agents:

```yaml
default_action: deny

rules:
  - name: my-git
    match:
      ssh_dest: "git@github.com"
      parent_process_name: git
    action: allow

  - name: interactive-ssh
    match:
      parent_process_name: bash
      is_in_known_hosts: true
    action: confirm
```

### Logging-only (no restrictions)

If you just want an audit trail without blocking anything:

```yaml
default_action: allow

# No rules needed — everything is allowed and logged.
# Check ~/.local/state/ssh-ag/ for YAML event files.
```

## Debugging policies

Use the `check` subcommand to see how the proxy evaluates your current shell:

```
$ ssh-agent-guard check
context:
  process_name: bash
  cmdline: /bin/bash
  exe_path: /usr/bin/bash
  local_cwd: /home/alice/src/myproject
  is_coding_agent: false
  ...
policy_evaluation:
  rules:
    - name: git-hosts
      matched: false
      mismatches: ["ssh_dest: empty, want git@github.com"]
    - name: coding-agents
      matched: false
      mismatches: ["is_coding_agent: want true, got false"]
result:
  action: allow
  rule: default
```

To check a specific process:

```
$ ssh-agent-guard check --pid 4521 --key SHA256:abc123
```

## Confirmation rate limiting

The `confirm.max_pending` setting limits the number of concurrent
pending confirmations.  When the limit is reached, additional confirm
requests are immediately denied.

```yaml
confirm:
  max_pending: 3    # default
```

This prevents a same-user process from flooding the confirmation UI
with rapid sign requests.  Rate-limited denials are logged with
`confirm_method: rate-limited`, include a `forensics` block (see
below), and appear in the journal as:

```
confirm: rate-limited (3/3 pending), denying npm → unknown
```

Set to `0` to disable the limit entirely.  The default of 3 is
sufficient for normal use — even aggressive git operations rarely
produce more than 2 concurrent sign requests.

## Tips

- **Start permissive, tighten gradually.** Begin with `default_action:
  allow` and a few `confirm` rules.  Review log files to understand
  your signing patterns before switching to default-deny.

- **Use `parent_process_name` over `process_name`.** The process
  connecting to the agent is almost always `ssh`.  The parent
  (`git`, `rsync`, `claude`) is usually what you care about.

- **Regex for complex patterns.** Prefix a match value with `~` to
  use Go regex syntax: `ssh_dest: "~^git@(github|gitlab)\\.com$"`.

- **Policy changes are live.** The proxy watches the policy file via
  inotify and reloads automatically.  No restart needed.

- **Log files are your friend.** Each signing event writes a YAML
  file to `~/.local/state/ssh-ag/` with full caller context.  Use
  these to discover what needs rules.

## Deny forensics

When a request is denied — whether by a deny rule, a declined
confirmation, rate limiting, or a missing confirmation method — the
log event includes an extra `forensics` block with additional context:

- **sign_request_num** — which sign request on this connection
  triggered the deny (1st? 15th?).
- **process_age** — time since the caller process started.  A freshly
  spawned process is more suspicious than a long-running shell.
- **rule_trace** — the full rule evaluation showing each rule, whether
  it matched, and specific mismatches (sign requests only; mutations
  do not go through policy evaluation).

This data is only collected on deny paths to avoid overhead on allowed
requests.  Example:

```yaml
decision: deny
rule: forwarded-unknown
forensics:
  sign_request_num: 1
  process_age: 3s
  rule_trace:
    - name: git-hosts
      action: allow
      matched: false
      mismatches:
        - "ssh_dest: want \"git@github.com\", got \"suspect-host.example.com\""
    - name: forwarded-unknown
      action: deny
      matched: true
```
