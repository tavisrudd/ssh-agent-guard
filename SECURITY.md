# Security Policy

## Status

**ssh-agent-guard is beta software.** It was recently extracted from a
personal dotfiles repository and has not undergone an independent
security review. While it includes a comprehensive test suite and has
been used in production on the author's machines, it may contain bugs
or design issues that affect security.

**Do not rely on ssh-agent-guard as your sole security boundary
without understanding its limitations.** Read the THREAT MODEL section
in ssh-agent-guard(1) before deploying.

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it privately
by emailing **tavis@damnsimple.com**. Do not open a public GitHub
issue for security-sensitive bugs.

Please include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment (what an attacker can do)

I will acknowledge receipt within 48 hours and aim to provide an
initial assessment within one week.

## Known Limitations

These are documented in the man page but bear repeating:

- **Same-user bypass**: Without filesystem-level socket protection,
  any process running as your user can connect directly to the
  upstream agent socket, bypassing the guard entirely. See SYSTEM
  SETUP in ssh-agent-guard(1).
- **Root compromise**: A root-level attacker can bypass all controls.
- **TOCTOU**: Caller identity is gathered once per connection,
  immediately after accept(2), by reading /proc for the PID
  obtained via SO_PEERCRED. If a process calls exec(2) after
  identity is captured, subsequent sign requests on that connection
  use the stale (pre-exec) identity. There is also a narrow race
  between connect(2) and the /proc reads where an exec could cause
  the proxy to read the post-exec identity instead of the original.
- **PID recycling**: Theoretically exploitable on systems with small
  PID ranges, though impractical in practice.
- **Environment assumptions**: The confirmation UI assumes sway/tmux.
  Other environments will need adapter code.
