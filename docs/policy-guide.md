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
as you discover new legitimate uses.  Use `--check` and log files to
find operations that need rules.

### Default-allow (recommended for getting started)

```yaml
default_action: allow

rules:
  - name: ai-tools
    match:
      env:
        CLAUDECODE: "1"
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

## Common scenarios

### Git hosting

Allow signing for well-known git hosts without confirmation:

```yaml
  - name: git-hosts
    match:
      ssh_dest: "git@github.com"
    action: allow

  # Multiple hosts
  - name: git-hosts-all
    match:
      ssh_dest: "~^git@(github\\.com|gitlab\\.com|codeberg\\.org)$"
    action: allow
```

### AI coding tools

AI tools that make SSH connections (git push, remote operations)
can be required to confirm via YubiKey:

```yaml
  # Claude Code
  - name: claude
    match:
      env:
        CLAUDECODE: "1"
    action: confirm

  # Any AI tool — match by ancestor process
  - name: ai-ancestors
    match:
      ancestor: [claude, cursor, copilot-agent]
    action: confirm
```

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

Containers connecting via bind-mounted sockets have incomplete
caller identity.  Default to deny:

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

Use `--check` to see how the proxy evaluates your current shell:

```
$ ssh-agent-guard --check
context:
  process_name: bash
  cmdline: /bin/bash
  local_cwd: /home/alice/src/myproject
  ...
policy_evaluation:
  rules:
    - name: git-hosts
      matched: false
      mismatches: ["ssh_dest: empty, want git@github.com"]
    - name: ai-tools
      matched: false
      mismatches: ["env.CLAUDECODE: empty, want 1"]
result:
  action: allow
  rule: default
```

To check a specific process:

```
$ ssh-agent-guard --check --pid 4521 --key SHA256:abc123
```

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
