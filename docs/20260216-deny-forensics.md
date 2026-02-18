# Deny forensics: richer context for denied requests

Date: 2026-02-16

## Context

When ssh-agent-guard denies a request (deny rule match, user-declined
confirmation, rate-limiting, or missing confirmation method), the log
already captures full caller identity.  But denied events are the most
security-relevant and warrant additional context that would be wasteful
to collect on every allowed request.

This adds richer forensic data on deny events only, structured so the
platform-specific parts (/proc on Linux, sysctl/libproc on macOS) are
isolated behind clear function boundaries aligned with the planned
`caller_linux.go` / `caller_darwin.go` split in `macos-support.md`.

## What to add

### Always collected (CallerContext, at connect time)

Cheap, useful for `check` output and all log events:

1. **exe_path** -- `readlink /proc/$pid/exe`.  Catches temp-dir
   binaries, argv[0] spoofing, and distinguishes Nix store paths.
   macOS: `proc_pidpath()`.

2. **uid/gid in log events** -- already in CallerContext from
   SO_PEERCRED, just not serialized to YAML.

### Collected on deny only (DenyForensics struct)

3. **Rule evaluation trace** -- reuses existing `EvaluateVerbose()`
   from policy.go.  Shows each rule, whether it matched, and the
   specific mismatches.  Entirely platform-neutral.

4. **Sign request count** -- which sign request on this connection
   triggered the deny (1st? 15th?).  Counter on ProxyAgent.
   Platform-neutral.

5. **Process age** -- time since process start.  A freshly-spawned
   process making agent requests is more suspicious than a long-running
   shell.  Linux: `/proc/$pid/stat` field 22.
   macOS: `sysctl KERN_PROC` -> `kp_proc.p_starttime`.

## File changes

### New: `forensics.go`

Platform-neutral struct definition and assembly function.

```go
type DenyForensics struct {
    SignRequestNum int                `yaml:"sign_request_num,omitempty"`
    ProcessAge     string             `yaml:"process_age,omitempty"`
    RuleTrace      []RuleCheckResult  `yaml:"rule_trace,omitempty"`
}

func collectDenyForensics(
    caller *CallerContext,
    session *SessionBindInfo,
    keyFingerprint string,
    policy *Policy,
    signRequestNum int,
) *DenyForensics
```

Calls platform-specific `readProcessAge(pid)` + platform-neutral
`policy.EvaluateVerbose()`.

### Modified: `policy.go`

Add YAML tags to `RuleCheckResult` so it can be used directly in both
`check` subcommand output and deny forensics logs:

```go
type RuleCheckResult struct {
    Name       string   `yaml:"name"`
    Action     string   `yaml:"action"`
    Matched    bool     `yaml:"matched"`
    Mismatches []string `yaml:"mismatches,omitempty"`
}
```

### Modified: `check.go`

Delete the parallel `checkRule` type.  Use `RuleCheckResult` directly
in `checkPolicyEvaluation.Rules`.

### Modified: `caller.go`

Add two platform-specific functions (move with the rest to
`caller_linux.go` / `caller_darwin.go` when the split happens):

```go
func readExePath(pid int32) string
func readProcessAge(pid int32) time.Duration
```

`readExePath`: `os.Readlink("/proc/$pid/exe")`.

`readProcessAge`: read `/proc/$pid/stat` field 22 (starttime in clock
ticks), get boot time from `/proc/stat` btime line (cached via
`sync.Once`), compute `time.Since(bootTime + starttime/CLK_TCK)`.

Add `ExePath` field to `CallerContext`, populated in
`getCallerContextFromPID()`.

### Modified: `logger.go`

Add fields to `logEvent`:

```go
UID       uint32         `yaml:"uid,omitempty"`
GID       uint32         `yaml:"gid,omitempty"`
ExePath   string         `yaml:"exe_path,omitempty"`
Forensics *DenyForensics `yaml:"forensics,omitempty"`
```

`buildSignEvent` and `buildMutationEvent`: populate uid, gid, exe_path
from CallerContext always.  Accept optional `*DenyForensics`, attach
when non-nil.

### Modified: `proxy.go`

Add `signCount int` to `ProxyAgent`, increment in `SignWithFlags`
and `Sign`.

In `evalAndConfirm`, before each `LogSign` call where the outcome is
deny, collect forensics:

```go
var forensics *DenyForensics
if result.Action == Deny {
    forensics = collectDenyForensics(
        p.caller, p.session,
        ssh.FingerprintSHA256(key),
        p.policy, p.signCount,
    )
}
p.logger.LogSign(p.caller, key, p.session, result, forensics)
```

This covers all deny paths: direct deny rule, confirm-declined,
rate-limited, and missing method.

Mutation methods: collect forensics with signCount=0 (no rule trace
since mutations bypass policy evaluation).

## Deny paths affected

| Scenario              | Code path                    | Has rule trace |
|-----------------------|------------------------------|----------------|
| Deny rule match       | evalAndConfirm -> LogSign    | Yes            |
| Confirm declined      | evalAndConfirm -> LogSign    | Yes            |
| Confirm rate-limited  | evalAndConfirm -> LogSign    | Yes            |
| Confirm method missing| evalAndConfirm -> LogSign    | Yes            |
| Mutation blocked      | Add/Remove/etc -> LogMutation| No             |

## Example log output (deny with forensics)

```yaml
timestamp: "2026-02-16T10:30:22"
trigger: sign
process_name: ssh
local_pid: 4521
uid: 1000
gid: 1000
exe_path: /nix/store/abc123-openssh-9.6p1/bin/ssh
ssh_dest: suspect-host.example.com
local_cwd: /home/alice/src
user_presence: local
decision: deny
rule: forwarded-unknown
config_sha256: a1b2c3...
local_proc_tree:
  - pid: 4521
    name: ssh
    command: ssh suspect-host.example.com
  - pid: 4500
    name: bash
    command: /bin/bash
forensics:
  sign_request_num: 1
  process_age: 3s
  rule_trace:
    - name: git-hosts
      action: allow
      matched: false
      mismatches:
        - "ssh_dest: want \"git@github.com\", got \"suspect-host.example.com\""
    - name: forwarded-known
      action: allow
      matched: false
      mismatches:
        - "is_in_known_hosts: want true, no session-bind dest"
    - name: forwarded-unknown
      action: deny
      matched: true
```

## macOS compatibility

Platform-specific functions to implement later:

| Function           | Linux                     | macOS                            |
|--------------------|---------------------------|----------------------------------|
| `readExePath`      | readlink `/proc/$pid/exe` | `proc_pidpath()` (libproc)       |
| `readProcessAge`   | `/proc/$pid/stat` field 22| sysctl KERN_PROC -> p_starttime  |

Both accessible for same-user processes without root.  These live in
`caller.go` today alongside the other /proc reads and will move to
`caller_linux.go` / `caller_darwin.go` when the split happens.
No build tags needed yet (consistent with rest of codebase).

## Verification

1. `go build` -- compiles
2. `go test ./...` -- existing tests pass
3. New tests:
   - `readExePath(int32(os.Getpid()))` returns a valid path
   - `readProcessAge(int32(os.Getpid()))` returns a positive duration
   - `collectDenyForensics` populates all fields
   - logEvent YAML includes `forensics:` block when present, omits
     when nil
   - logEvent YAML includes `uid:`, `gid:`, `exe_path:` fields
4. Manual: `ssh-agent-guard check` shows `exe_path`
5. Manual: trigger a deny and inspect the YAML log for forensics block
