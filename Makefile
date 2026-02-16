PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man

LDFLAGS ?= -s -w

# Documentation sources
DOCS     := $(wildcard docs/*.md)
MAN1_M4  := man/ssh-agent-guard.1.md.m4
MAN5_M4  := man/ssh-agent-guard-policy.5.md.m4

.PHONY: build test clean install cross docs man readme

build:
	go build -ldflags="$(LDFLAGS)" -o ssh-agent-guard .

test:
	go test -race -count=1 ./...

# Generate all documentation (README + man pages)
docs: readme man

# Generate README.md from template + fragments
readme: README.md
README.md: README.md.m4 $(DOCS)
	m4 $< > $@

# Generate man pages: .m4 → .md (m4) → roff (go-md2man)
man: ssh-agent-guard.1 ssh-agent-guard-policy.5

ssh-agent-guard.1: $(MAN1_M4) $(DOCS)
	m4 $< | go-md2man > $@

ssh-agent-guard-policy.5: $(MAN5_M4) $(DOCS)
	m4 $< | go-md2man > $@

clean:
	rm -f ssh-agent-guard

install: build
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 ssh-agent-guard $(DESTDIR)$(BINDIR)/
	install -m 755 scripts/ssh-ag-confirm $(DESTDIR)$(BINDIR)/
	install -m 755 scripts/ssh-ag-deny $(DESTDIR)$(BINDIR)/
	install -m 755 scripts/ssh-ag-render-status $(DESTDIR)$(BINDIR)/
	install -d $(DESTDIR)$(MANDIR)/man1 $(DESTDIR)$(MANDIR)/man5
	install -m 644 ssh-agent-guard.1 $(DESTDIR)$(MANDIR)/man1/
	install -m 644 ssh-agent-guard-policy.5 $(DESTDIR)$(MANDIR)/man5/

cross:
	GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o ssh-agent-guard-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o ssh-agent-guard-linux-arm64 .
