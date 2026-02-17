# Security Review — 2026-02-16

Reviewed by: Claude Opus 4.6 (Anthropic CLI agent), at the request of Tavis Rudd.

Scope: full codebase read (all .go source, tests, scripts, flake.nix, go.mod)
plus all documentation (README, SECURITY.md, docs/*.md, man page templates).

## Executive Summary

The codebase is well-designed with an honest, well-documented threat model.
No critical vulnerabilities found. The architecture is sound — kernel-verified
PID via SO_PEERCRED, no custom crypto, minimal dependencies, atomic policy
updates. The primary weaknesses are in the confirmation bypass path (FIFO
injection) and some documentation inconsistencies. Overall quality is high
for a beta project.

---

## Part 1: Red Team Findings

### M1. FIFO Result Injection Bypasses Confirmation (Medium)

**File:** `confirm_pin.go:39-44,64-72`

A same-user attacker can bypass PIN/touch confirmation by racing to write
`"allow"` to the FIFO before the legitimate `ssh-ag-confirm` script:

1. Monitor `~/.local/state/ssh-ag/pending/` with inotify for new `.result`
   FIFOs
2. Open the FIFO for writing
3. Write `"allow\n"`

The FIFO path is predictable (well-known state dir), the race window is
large (up to 120s for PIN), and the daemon accepts the bare string `"allow"`
with no authentication.

**Why this matters beyond same-user socket bypass:** If Landlock/systemd
sandboxing protects the upstream socket (as the docs recommend), an attacker
blocked from the upstream socket may still be able to write to the state
directory. The FIFO injection becomes a real escalation path that bypasses
the sandboxing.

**Mitigation options:**
- HMAC-sign the FIFO response using a session nonce (the daemon generates a
  random nonce in the request YAML; the confirm script includes it in the
  FIFO response)
- Move the pending/confirm dirs under the same protected directory as the
  upstream socket
- At minimum, document this as a known limitation alongside the same-user
  bypass

### M2. Extension Parse Failure Silently Drops Forwarding Context (Medium)

**File:** `proxy.go:155-176`

If a session-bind message fails to parse, the extension is still forwarded
to upstream, but `p.session` remains nil. Subsequent sign requests are
evaluated without forwarding context — `is_forwarded` rules won't fire.

A custom SSH client (or a client sending a malformed session-bind) would
effectively bypass all forwarding policy rules. While OpenSSH generates
valid messages, the proxy should fail closed: if session-bind was received
but unparseable, set a flag so policy can deny.

This is mitigated by the fact that any client choosing not to send
session-bind at all has the same effect. But it's still worth logging more
prominently (currently just `log.Printf`).

### M3. Default Action Footgun (Medium)

**File:** `policy.go:405`

When a policy file **exists** but omits `default_action`, the Go struct
default is `"allow"`. When **no** policy file exists, the default is
`confirm` (safe). This creates a footgun:

```yaml
# User writes this thinking "I only want these rules":
rules:
  - name: deny-forwarded
    match:
      is_forwarded: true
    action: deny
# Result: everything NOT forwarded is silently allowed
```

The README doesn't warn about this gap. Options:
- Require `default_action` as a mandatory field (reject files without it)
- Change the struct default to `"confirm"` to match the no-file behavior
- Add a prominent warning in the docs

### L1. hasActiveDisplay() Race with Swaylock (Low)

**File:** `confirm.go:248-319`

The function makes sequential external calls (swaymsg version check → pgrep
swaylock → swaymsg get_outputs → jq). Between the "swaylock not running"
check and returning true, swaylock could start. This could select the touch
path when the screen is locked — the user wouldn't see the status bar prompt
but the YubiKey would still accept a touch.

Low severity because: (a) the race window is small, (b) swaylock starting
at that exact moment is unlikely, (c) touch still requires physical
presence.

### L2. No Rate Limiting on Confirmation (Low)

A malicious process can flood sign requests that trigger `confirm` rules,
causing:
- Dozens of pending FIFOs and request files in the state directory
- Status bar flicker
- User confusion about which request is legitimate (touch fatigue)

### L3. Socket chmod Race (Low, non-exploitable in practice)

**File:** `main.go:100-109`

```go
listener, err := net.Listen("unix", listenPath)
// window here where socket has umask-dependent perms
os.Chmod(listenPath, 0600)
```

Go's `net.Listen("unix", ...)` creates the socket with `0777 & ~umask`.
With typical umask 0022, the socket is briefly 0755. Non-exploitable because
`$XDG_RUNTIME_DIR` is 0700, so only same-user processes can reach it anyway.
Could be hardened by setting umask before listen.

### L4. Log Files World-Readable (Low)

**File:** `logger.go:107,492`

State dir: 0755, log files: 0644. On a multi-user system, other users can
read key fingerprints, SSH destinations, process trees, and environment
variables from the log files. Fine for single-user workstation; information
leak on shared systems.

### L5. SSH Destination Parser Edge Cases (Low)

**File:** `caller.go:362-398`

The `--` (end-of-options) marker is treated as a generic long flag and
skipped. After `--`, all subsequent arguments should be treated as
positional. A crafted cmdline like `ssh -- -trap-arg real-dest` would parse
`-trap-arg` as a flag. Low impact because the attacker controls their own
process and could simply not use ssh.

Also: `extractSSHDest` identifies ssh commands by
`processName(args[0]) == "ssh"` which checks for exactly "ssh". A binary
named "ssh2" or "autossh" wouldn't be parsed. This is a false-negative
rather than a security issue, but worth noting for policy accuracy.

### L6. Glob Matcher Exponential Worst Case (Low)

**File:** `policy.go:309-342`

`deepGlob` has O(2^n) worst case with patterns like `*a*a*a*a*b`. Only
exploitable via the policy file, which the user writes themselves. Could
cause CPU spikes during policy evaluation if a pathological pattern is
accidentally written.

### I1. Environment Variables Are Self-Attested (Informational)

**File:** `caller.go:96`

`CLAUDECODE`, `SSH_CONNECTION`, etc. are read from `/proc/pid/environ`,
which reflects whatever the process chose to set. A malicious process can
set `CLAUDECODE=1` to appear as Claude, or clear it to hide. Correctly
documented in `caller-identification.md` lines 17-18, but worth emphasizing
in the policy guide that env-based rules are advisory, not security
boundaries.

### I2. Config SHA256 Race During Long Confirmations (Informational)

**File:** `logger.go:279-284`

Correctly documented in a code comment. If a policy reload occurs during a
120s PIN confirmation wait, the logged SHA may be one version newer than the
policy that evaluated the request. Not a security issue, but could
complicate forensic analysis.

---

## Part 2: Documentation Factual Accuracy

### Inconsistency: TOCTOU Description Contradicts Between Files

**SECURITY.md line 39:** "a process that exec(2)s between connecting and
signing will be evaluated with its **pre-exec** identity"

**caller-identification.md line 126-128:** "the reads will see the
**post-exec** identity while the kernel's SO_PEERCRED still reflects the
pre-exec PID"

These describe two different scenarios:
- **SECURITY.md** describes exec AFTER the proxy reads /proc (common case)
  — identity is frozen from the initial read, so the pre-exec identity
  persists for all operations on that connection. Correct for this case.
- **caller-identification.md** describes exec BETWEEN connect(2) and /proc
  reads (rare race) — the proxy would see the post-exec identity. Also
  correct for this specific race.

Both documents are individually correct for the scenario they describe, but
read together they seem contradictory. Suggest unifying the language: the
proxy reads identity once at accept-time, and there's a narrow race where
exec could change what /proc shows between connect(2) and the reads.

### Verified Accurate Claims

| Claim                                    | Location         | Verdict                     |
|------------------------------------------|------------------|-----------------------------|
| SO_PEERCRED kernel-verified, unfakeable  | caller-id        | **Correct**                 |
| OpenSSH 8.9+ for session-bind            | multiple files   | **Correct**                 |
| FIDO2 resident keys require OpenSSH 8.2+ | defense-in-depth | **Correct**                 |
| Landlock is Linux 5.13+, unprivileged    | system-setup     | **Correct**                 |
| CAP_DAC_READ_SEARCH bypasses dir perms   | system-setup     | **Correct**                 |
| CVE-2023-38408 (forwarding RCE)          | why-this-matters | **Correct** (CVSS 9.8)      |
| CVE-2025-55284 (CC allowlist bypass)     | why-this-matters | **Correct**                 |
| CVE-2025-66032 (CC cmd validation)       | why-this-matters | **Correct**                 |
| Matrix.org 2019 incident                 | why-this-matters | **Correct**                 |
| Codecov 2021 incident                    | why-this-matters | **Correct**                 |
| guardian-agent unmaintained              | README           | **Correct** (last act 2019) |
| MITRE ATT&CK T1552.004, T1563.001        | why-this-matters | **Correct technique IDs**   |
| ssh-add -h limitations                   | why-this-matters | **Correct**                 |
| Hashed known_hosts irreversible (HMAC)   | forwarding       | **Correct**                 |
| ~1ms per operation overhead              | README           | **Plausible** (/proc fast)  |

### Minor Nits

- **why-this-matters.md line 79:** Describes Claude Code CVEs as "command
  injection vulnerabilities" — CVE-2025-55284 is more accurately an
  allowlist bypass / exfiltration issue. CVE-2025-66032 is a command
  validation bypass. "Prompt injection leading to unauthorized command
  execution" would be more precise as a collective description.
- **defense-in-depth.md line 16:** `ssh-keygen -t ed25519-sk` — correct
  syntax, though worth noting this requires a FIDO2-capable key (YubiKey 5+,
  SoloKey v2+), not just any YubiKey.

---

## Part 3: Code Quality Observations

**Positive:**
- No unsafe code, no custom crypto, minimal dependency surface
- Thread safety is well-handled (RWMutex for policy, atomic.Pointer for
  config)
- Atomic policy updates — bad configs don't replace good ones
- Test coverage on critical paths (policy evaluation, proxy blocking,
  session-bind)
- Fail-closed on missing YubiKey (confirm degrades to deny)
- Connection-scoped upstream connections (no shared upstream connection)

**Test gaps:**
- No tests for the FIFO/PIN confirmation path
- No tests for `hasActiveDisplay()` logic
- No tests for `extractSSHDest` with combined flags like `-NTfp 22`
- No negative tests for malformed session-bind payloads

---

## Prioritized Recommendations

1. **M1 (FIFO injection):** Add authentication to the FIFO response, or
   co-locate the pending dir with the protected upstream socket dir
2. **M3 (default action):** Require `default_action` or change the struct
   default to match the no-file behavior
3. **TOCTOU docs:** Unify the language across SECURITY.md and
   caller-identification.md
4. **M2 (session-bind parse failure):** Log more prominently and consider a
   fail-closed flag
5. **Test coverage:** Add FIFO confirmation and malformed session-bind tests
