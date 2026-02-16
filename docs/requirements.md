- **Linux** — uses SO_PEERCRED(7), /proc, and PID namespaces.
  No macOS or BSD support.
- **OpenSSH 8.9+** — required for `session-bind@openssh.com`, which
  provides forwarded agent detection, destination host identification,
  and `ssh_dest` session-bind fallback, `is_in_known_hosts`, and `is_forwarded`
  policy matching.
  Without it the guard still works but those fields are always empty.
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
