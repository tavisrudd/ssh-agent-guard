package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Destination naming for session-bind host keys.
//
// The proxy sees a destination only as a host key. It names it from, in
// order: plaintext known_hosts entries; hashed known_hosts entries
// (|1|salt|HMAC-SHA1(salt, host)) matched against candidate names taken
// from the user's ssh config; the in-memory session carry-over
// (sessionNames); and names learned from earlier direct connections
// (LearnedNames). A key that no source names is shown by fingerprint.

// hostCandidate is a string that ssh may have hashed into known_hosts
// (match) and the name to show when it does (name). For "Host curry" with
// "Hostname 10.66.0.10", both "curry" and "10.66.0.10" are candidates named
// "curry".
type hostCandidate struct {
	match string
	name  string
}

// sshConfigScan is what the proxy needs from ssh_config(5).
type sshConfigScan struct {
	candidates      []hostCandidate
	knownHostsFiles []string // expanded paths, deduplicated
	configFiles     []string // config files read, for change detection
}

const maxSSHConfigIncludeDepth = 8

type sshConfigBlock struct {
	hosts    []string // literal (non-wildcard) host names of the block
	hostname string
	port     string
}

// scanSSHConfig reads an ssh config file and its includes. It does not
// evaluate Host/Match conditions; it collects every literal host name,
// Hostname, Port and known_hosts file setting.
func scanSSHConfig(path, home string) *sshConfigScan {
	s := &sshConfigScan{}
	var userKH, globalKH []string
	var blocks []*sshConfigBlock
	seenFiles := map[string]bool{}

	var readFile func(path string, depth int)
	readFile = func(path string, depth int) {
		if depth > maxSSHConfigIncludeDepth || seenFiles[path] {
			return
		}
		seenFiles[path] = true
		f, err := os.Open(path)
		if err != nil {
			return
		}
		defer f.Close()
		s.configFiles = append(s.configFiles, path)

		cur := &sshConfigBlock{} // settings before the first Host apply globally
		blocks = append(blocks, cur)
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			key, args := splitSSHConfigLine(scanner.Text())
			if key == "" {
				continue
			}
			switch key {
			case "include":
				for _, pat := range args {
					pat = expandTilde(pat, home)
					if !filepath.IsAbs(pat) {
						pat = filepath.Join(home, ".ssh", pat)
					}
					matches, _ := filepath.Glob(pat)
					sort.Strings(matches)
					for _, m := range matches {
						readFile(m, depth+1)
					}
				}
			case "host":
				cur = &sshConfigBlock{}
				blocks = append(blocks, cur)
				for _, a := range args {
					if literalHostPattern(a) {
						cur.hosts = append(cur.hosts, a)
					}
				}
			case "match":
				cur = &sshConfigBlock{}
				blocks = append(blocks, cur)
				for i := 0; i+1 < len(args); i++ {
					if strings.EqualFold(args[i], "host") || strings.EqualFold(args[i], "originalhost") {
						for _, h := range strings.Split(args[i+1], ",") {
							if literalHostPattern(h) {
								cur.hosts = append(cur.hosts, h)
							}
						}
					}
				}
			case "hostname":
				if len(args) > 0 && cur.hostname == "" {
					cur.hostname = args[0]
				}
			case "port":
				if len(args) > 0 && cur.port == "" {
					cur.port = args[0]
				}
			case "userknownhostsfile":
				userKH = append(userKH, args...)
			case "globalknownhostsfile":
				globalKH = append(globalKH, args...)
			}
		}
	}
	readFile(path, 0)

	seen := map[hostCandidate]bool{}
	add := func(match, name, port string) {
		for _, m := range []string{match, bracketPort(match, port)} {
			c := hostCandidate{match: m, name: name}
			if m != "" && !seen[c] {
				seen[c] = true
				s.candidates = append(s.candidates, c)
			}
		}
	}
	for _, b := range blocks {
		display := b.hostname
		if len(b.hosts) == 1 {
			display = b.hosts[0]
		}
		for _, h := range b.hosts {
			add(h, h, b.port)
		}
		if b.hostname != "" && !strings.Contains(b.hostname, "%") {
			add(b.hostname, display, b.port)
		} else if len(b.hosts) == 1 && strings.Contains(b.hostname, "%h") {
			add(strings.ReplaceAll(b.hostname, "%h", b.hosts[0]), display, b.port)
		}
	}

	s.knownHostsFiles = expandKnownHostsFiles(append(userKH, globalKH...), home, s.candidates)
	return s
}

// splitSSHConfigLine returns the lower-cased keyword and its arguments,
// honouring "key=value", comments and double quotes.
func splitSSHConfigLine(line string) (string, []string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", nil
	}
	if i := strings.IndexAny(line, " \t="); i > 0 {
		key := strings.ToLower(line[:i])
		rest := strings.TrimLeft(line[i:], " \t")
		rest = strings.TrimPrefix(rest, "=")
		return key, splitSSHConfigArgs(rest)
	}
	return strings.ToLower(line), nil
}

func splitSSHConfigArgs(s string) []string {
	var args []string
	var cur strings.Builder
	inQuote, have := false, false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			have = true
		case !inQuote && (r == ' ' || r == '\t'):
			if have {
				args = append(args, cur.String())
				cur.Reset()
				have = false
			}
		case !inQuote && r == '#':
			if have {
				args = append(args, cur.String())
			}
			return args
		default:
			cur.WriteRune(r)
			have = true
		}
	}
	if have {
		args = append(args, cur.String())
	}
	return args
}

func literalHostPattern(p string) bool {
	return p != "" && !strings.ContainsAny(p, "*?!%")
}

func bracketPort(host, port string) string {
	if port == "" || port == "22" || strings.HasPrefix(host, "[") {
		return ""
	}
	return fmt.Sprintf("[%s]:%s", host, port)
}

func expandTilde(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}

// expandKnownHostsFiles expands known_hosts file settings into paths:
// ~, %d (home), %u (user) and %% directly; %h, %n and %k once per
// candidate name, keeping only files that exist. The OpenSSH defaults are
// always included.
func expandKnownHostsFiles(settings []string, home string, candidates []hostCandidate) []string {
	username := ""
	if u, err := user.Current(); err == nil {
		username = u.Username
	}
	all := append([]string{
		"~/.ssh/known_hosts", "~/.ssh/known_hosts2",
		"/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2",
	}, settings...)

	seen := map[string]bool{}
	var out []string
	addPath := func(p string, mustExist bool) {
		if p == "" || seen[p] {
			return
		}
		if mustExist {
			if _, err := os.Stat(p); err != nil {
				return
			}
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, setting := range all {
		if strings.EqualFold(setting, "none") {
			continue
		}
		p := expandTilde(setting, home)
		p = strings.ReplaceAll(p, "%d", home)
		p = strings.ReplaceAll(p, "%u", username)
		if !strings.ContainsAny(p, "%") {
			addPath(p, false)
			continue
		}
		if strings.Contains(strings.ReplaceAll(p, "%%", ""), "%") {
			names := map[string]bool{}
			for _, c := range candidates {
				names[c.match] = true
				names[c.name] = true
			}
			for n := range names {
				q := strings.NewReplacer("%h", n, "%n", n, "%k", n).Replace(p)
				q = strings.ReplaceAll(q, "%%", "%")
				if !strings.Contains(q, "%") {
					addPath(q, true)
				}
			}
			continue
		}
		addPath(strings.ReplaceAll(p, "%%", "%"), false)
	}
	return out
}

// matchHashedHost reports whether a hashed known_hosts host field
// (|1|base64 salt|base64 HMAC-SHA1) is the hash of name.
func matchHashedHost(salt, sum []byte, name string) bool {
	mac := hmac.New(sha1.New, salt)
	mac.Write([]byte(name))
	return hmac.Equal(mac.Sum(nil), sum)
}

// LoadDestinationNames builds a resolver from the user's ssh config and
// every known_hosts file it names. It returns the resolver and the files
// it depends on, for change detection.
func LoadDestinationNames(home string) (*KnownHostsResolver, []string) {
	scan := scanSSHConfig(filepath.Join(home, ".ssh", "config"), home)
	r := NewKnownHostsResolver(scan.knownHostsFiles...)
	matched := r.MatchHashed(scan.candidates)
	log.Printf("known_hosts: %d host keys from %d files, %d hashed entries named from %d ssh config candidates",
		len(r.known), len(scan.knownHostsFiles), matched, len(scan.candidates))
	deps := append(append([]string(nil), scan.configFiles...), scan.knownHostsFiles...)
	return r, deps
}

// fileSignature summarises the mtimes and sizes of paths, so a poller can
// notice edits to ssh config or known_hosts files.
func fileSignature(paths []string) string {
	var b strings.Builder
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil {
			fmt.Fprintf(&b, "%s %d %d\n", p, info.ModTime().UnixNano(), info.Size())
		} else {
			fmt.Fprintf(&b, "%s missing\n", p)
		}
	}
	return b.String()
}

// LearnedNames persists host key fingerprint → name pairs learned when a
// local ssh authenticated directly to a host whose key is in known_hosts but
// that nothing else names (typically a hashed entry for a host not in the
// ssh config). The file lives in the proxy's state directory, written only
// by the proxy.
type LearnedNames struct {
	mu    sync.Mutex
	path  string
	byFP  map[string]string
	order []string
}

const maxLearnedNames = 1024

var learnedNameRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,253}$`)

// learnedNames is the process-wide store; nil disables learning (tests).
var learnedNames *LearnedNames

func LoadLearnedNames(path string) *LearnedNames {
	l := &LearnedNames{path: path, byFP: map[string]string{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("learned-hosts: %v", err)
		}
		return l
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || !strings.HasPrefix(fields[0], "SHA256:") || !learnedNameRe.MatchString(fields[1]) {
			continue
		}
		if _, ok := l.byFP[fields[0]]; !ok {
			l.order = append(l.order, fields[0])
		}
		l.byFP[fields[0]] = fields[1]
	}
	return l
}

func (l *LearnedNames) Lookup(fp string) string {
	if l == nil {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.byFP[fp]
}

// Learn records name for fp and rewrites the file when it changes. The
// user@ prefix is dropped; names with characters outside a hostname's are
// ignored.
func (l *LearnedNames) Learn(fp, name string) {
	if l == nil || fp == "" {
		return
	}
	if i := strings.LastIndex(name, "@"); i >= 0 {
		name = name[i+1:]
	}
	if !learnedNameRe.MatchString(name) {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.byFP[fp] == name {
		return
	}
	if _, ok := l.byFP[fp]; !ok {
		l.order = append(l.order, fp)
		if len(l.order) > maxLearnedNames {
			delete(l.byFP, l.order[0])
			l.order = l.order[1:]
		}
	}
	l.byFP[fp] = name
	log.Printf("learned-hosts: %s → %s", fp[:min(len(fp), 19)], name)
	l.saveLocked()
}

func (l *LearnedNames) saveLocked() {
	var b strings.Builder
	fmt.Fprintf(&b, "# ssh-agent-guard learned destination names (host key fingerprint, name); written by the proxy\n")
	for _, fp := range l.order {
		fmt.Fprintf(&b, "%s %s\n", fp, l.byFP[fp])
	}
	tmp := fmt.Sprintf("%s.%d.tmp", l.path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, []byte(b.String()), 0600); err != nil {
		log.Printf("learned-hosts: write: %v", err)
		return
	}
	if err := os.Rename(tmp, l.path); err != nil {
		os.Remove(tmp)
		log.Printf("learned-hosts: rename: %v", err)
	}
}

// watchDestinationNames reloads the resolver when the ssh config or a
// known_hosts file changes, so newly accepted host keys are named without
// a restart.
func watchDestinationNames(home string, store interface {
	Store(*KnownHostsResolver)
}, deps []string) {
	sig := fileSignature(deps)
	for range time.Tick(10 * time.Second) {
		if s := fileSignature(deps); s != sig {
			r, newDeps := LoadDestinationNames(home)
			store.Store(r)
			deps = newDeps
			sig = fileSignature(deps)
		}
	}
}
