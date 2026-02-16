- **Linux only** (macOS support planned) — uses `SO_PEERCRED(7)` for
  kernel-verified caller identification and `/proc` for process context
  (command line, ancestry, environment, PID namespaces).  macOS has
  equivalent APIs (`LOCAL_PEERPID`, `KERN_PROCARGS2`, `proc_pidinfo`)
  that enable a near-complete port.
- **OpenSSH 8.9+** — required for `session-bind@openssh.com`, which
  enables forwarded agent detection and the `ssh_dest`,
  `is_in_known_hosts`, and `is_forwarded` policy fields.
  Without it the guard still works but cannot identify remote
  destinations or detect forwarding.
- **Go 1.24+** — for building from source.

### Optional dependencies

- **yubikey-personalization** — provides `ykchalresp` and `ykinfo`,
  used for YubiKey HMAC confirmation.  When installed via the Nix flake,
  these are included in the wrapper's PATH.  Without a YubiKey,
  `action: confirm` rules degrade to `deny`.
- **tmux** — used for PIN confirmation popups (`ssh-ag-confirm`
  runs in a tmux popup), status display (sets `@ssh_ag_status` user
  option), and forwarded session detection.
- **sway** — `hasActiveDisplay()` uses `swaymsg` to check compositor
  reachability and detect `swaylock`.  Other Wayland/X11 compositors
  would need equivalent logic.
- **jq** — used by `hasActiveDisplay()` to parse sway output JSON.
- **i3status-rs** — `ssh-ag-render-status` writes pango markup to a
  file watched by i3status-rs.  Other status bars would need a
  different renderer.

The core proxy (policy evaluation, caller identification, logging)
has no compositor or multiplexer dependencies — only the confirmation
UI and status rendering do.

### Performance

The proxy adds negligible latency (~1ms per operation).  The main
cost is `/proc` reads for caller identification, which are
memory-backed and fast on any modern kernel.
