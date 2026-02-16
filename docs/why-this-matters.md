# Why this matters

SSH keys are high-value targets.  A single compromised key can open
connections, push code, and authenticate as you to any server that
trusts it.  This page collects real-world incidents, risk framework
references, and the specific threat that AI coding tools introduce.

## The risk in numbers

SSH key compromise is a well-documented attack technique tracked by
major security frameworks:

- **MITRE ATT&CK [T1552.004]** (Unsecured Credentials: Private
  Keys) — documents adversaries searching for SSH keys on
  compromised systems.  Used by APT29 (SolarWinds), TeamTNT,
  Scattered Spider, and Rocke for lateral movement and persistence.
- **MITRE ATT&CK [T1563.001]** (Remote Service Session Hijacking:
  SSH Hijacking) — documents hijacking SSH agent sockets for
  lateral movement.  Used by UNC3886 via the MEDUSA rootkit.
- **OWASP Top 10 A07:2021** (Identification and Authentication
  Failures) — covers credential theft and session hijacking,
  including SSH key compromise.
- **Verizon DBIR** consistently reports stolen credentials as the
  most common initial access vector, with SSH keys being a subset
  of this category.

[T1552.004]: https://attack.mitre.org/techniques/T1552/004/
[T1563.001]: https://attack.mitre.org/techniques/T1563/001/

## Real-world incidents

### Matrix.org (2019)

A developer SSH'd into a compromised Jenkins server with agent
forwarding enabled (`ForwardAgent yes`).  The attacker hijacked the
forwarded agent to access 19 production hosts, compromising the
production database, package signing keys, and password hashes.

Their post-mortem concluded: "SSH agent forwarding is incredibly
unsafe, and in general you should never use it."

ssh-agent-guard's `is_forwarded` and `is_in_known_hosts` policy
fields exist specifically for this scenario — restricting which
remote destinations can use your forwarded keys.

Sources:
- [Post-mortem and remediations](https://matrix.org/blog/2019/05/08/post-mortem-and-remediations-for-apr-11-security-incident/)
- [Initial disclosure](https://matrix.org/blog/2019/04/11/we-have-discovered-and-addressed-a-security-breach-updated-2019-04-12/)

### OpenSSH agent forwarding RCE (CVE-2023-38408)

All OpenSSH versions before 9.3p2 were vulnerable to remote code
execution through the forwarded ssh-agent's PKCS#11 provider
loading.  An attacker controlling a remote server could achieve
RCE on the machine running the forwarded agent.  CVSS 9.8.

This is a protocol-level vulnerability in agent forwarding itself,
not a misconfiguration.  It affected every default OpenSSH
installation for over a decade.

Source: [Qualys advisory](https://blog.qualys.com/vulnerabilities-threat-research/2023/07/19/cve-2023-38408-remote-code-execution-in-opensshs-forwarded-ssh-agent)

### Codecov (2021)

Attackers modified the Codecov bash uploader to exfiltrate
environment variables — including SSH keys and tokens — from CI
environments.  Hundreds of customers were affected.  This is
a supply-chain attack on key material, the kind of threat that
hardware-backed keys prevent (the key can't be exfiltrated) and
that ssh-agent-guard logs (unauthorized key use is visible).

### Supply chain attacks on developer tools

AI coding tools, IDE extensions, and npm/PyPI packages run with
the developer's full permissions, including access to
`SSH_AUTH_SOCK`.  These are not hypothetical risks:

- **Claude Code** had multiple command injection vulnerabilities
  (CVE-2025-55284, CVE-2025-66032) that could be triggered via
  prompt injection — malicious instructions embedded in files
  or web pages that the tool processes.
- Any tool that can run `ssh` or connect to `SSH_AUTH_SOCK` can
  use your keys.  The SSH agent does not distinguish between
  `git push origin main` initiated by you and a connection
  initiated by a compromised dependency.

## What the SSH agent protocol doesn't do

The ssh(1) man page explicitly warns:

> Agent forwarding should be enabled with caution.  Users with
> the ability to bypass file permissions on the remote host (for
> the agent's UNIX-domain socket) can access the local agent
> through the forwarded connection.  An attacker cannot obtain
> key material from the agent, however they can perform operations
> on the keys that enable them to authenticate using the identities
> loaded into the agent.

The agent protocol has no built-in mechanism to verify:

1. **Who** is making the request (which process, which user
   initiated it)
2. **Where** they're connecting (which server, which service)
3. **Why** (what operation triggered the connection)

OpenSSH 8.9+ added [destination constraints] (`ssh-add -h`) which
restrict keys to specific hosts at the protocol level.  This is
a significant improvement but has limitations:

- Requires all participating hosts to run OpenSSH 8.9+
- Only works for SSH authentication (not git signing, age
  decryption, or other uses of SSH keys)
- Must be configured per-key at `ssh-add` time (no dynamic policy)
- Cannot distinguish callers — a compromised process and a
  legitimate one look identical to the agent

ssh-agent-guard is complementary: it adds caller identification,
dynamic policy, and audit logging on top of whatever the agent
itself provides.

[destination constraints]: https://www.openssh.org/agent-restrict.html

## The AI agent problem

The name "ssh-agent-guard" has a double meaning.  You're guarding
the ssh-agent, but you're also guarding *against* agents — the AI
agents that increasingly run on developer workstations: Claude Code,
Cursor, GitHub Copilot, and others.

These tools need SSH access to do useful work (pushing code,
pulling dependencies, connecting to dev servers).  But they also
process untrusted input — repository contents, web pages, user
prompts that may contain injected instructions.  A prompt injection
attack against an AI coding tool with SSH access is functionally
equivalent to a compromised process with access to your agent
socket.

ssh-agent-guard lets you have it both ways: allow AI tools to use
your keys for their intended purpose (git operations to known
hosts) while requiring confirmation or denying access for anything
else.  The `env: { CLAUDECODE: "1" }` policy field exists for
exactly this.
