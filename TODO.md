# TODO

- Add examples of bash/shell integration to docs (bashrc setup,
  verifying SSH_AUTH_SOCK points to the proxy, shell integration
  best practices)
- Consider making hasActiveDisplay() pluggable for non-sway
  compositors (currently hardcoded to swaymsg/swaylock in
  confirm.go)
- Consider goreleaser for automated cross-compilation releases
  (Makefile has manual cross target, CI builds but doesn't publish)
- Render man pages to markdown for GitHub browsing (mandoc
  -Tmarkdown; sources are .md.m4 → go-md2man → roff today)
- Address hasActiveDisplay() race condition from security review
  (swaylock can start between check and return)
- Add release publishing to CI workflow (related to goreleaser
  item; currently only runs test/build/vet/vulncheck)
