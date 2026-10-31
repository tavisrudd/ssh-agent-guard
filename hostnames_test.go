package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func hashedKnownHostsLine(t *testing.T, host string, key ssh.PublicKey) string {
	t.Helper()
	salt := make([]byte, 20)
	rand.Read(salt)
	mac := hmac.New(sha1.New, salt)
	mac.Write([]byte(host))
	return "|1|" + base64.StdEncoding.EncodeToString(salt) + "|" +
		base64.StdEncoding.EncodeToString(mac.Sum(nil)) + " " +
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) + "\n"
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func candidateNames(cs []hostCandidate) map[string]string {
	m := map[string]string{}
	for _, c := range cs {
		m[c.match] = c.name
	}
	return m
}

func TestScanSSHConfig(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".ssh", "config"), `
UserKnownHostsFile ~/.ssh/known_hosts ~/.ssh/known_hosts.d/%h
Include config.d/*

Host *
  ServerAliveInterval 60
`)
	writeFile(t, filepath.Join(home, ".ssh", "config.d", "10-personal"), `
Match host nano exec "host nano >/dev/null 2>&1"
  Hostname nano
Host nano
  Hostname nano.local
  ForwardAgent yes
Host curry
  Hostname 10.66.0.10
Host box
  Hostname=box.example.org
  Port 2222
Host *.example.com web?
  User x
`)
	writeFile(t, filepath.Join(home, ".ssh", "known_hosts.d", "curry"), "")

	s := scanSSHConfig(filepath.Join(home, ".ssh", "config"), home)
	got := candidateNames(s.candidates)
	want := map[string]string{
		"nano":                   "nano",
		"nano.local":             "nano",
		"curry":                  "curry",
		"10.66.0.10":             "curry",
		"box":                    "box",
		"box.example.org":        "box",
		"[box.example.org]:2222": "box",
		"[box]:2222":             "box",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("candidate %q → %q, want %q", k, got[k], v)
		}
	}
	for k := range got {
		if strings.ContainsAny(k, "*?") {
			t.Errorf("wildcard candidate %q", k)
		}
	}
	if len(s.configFiles) != 2 {
		t.Errorf("config files %v", s.configFiles)
	}
	var sawPerHost bool
	for _, f := range s.knownHostsFiles {
		if f == filepath.Join(home, ".ssh", "known_hosts.d", "curry") {
			sawPerHost = true
		}
		if strings.Contains(f, "%") {
			t.Errorf("unexpanded known_hosts path %q", f)
		}
	}
	if !sawPerHost {
		t.Errorf("per-host known_hosts file missing from %v", s.knownHostsFiles)
	}
}

func TestHashedKnownHostsNamedFromConfig(t *testing.T) {
	home := t.TempDir()
	curry := testSigner(t).PublicKey()
	stranger := testSigner(t).PublicKey()
	writeFile(t, filepath.Join(home, ".ssh", "config"), "Host curry\n  Hostname 10.66.0.10\n")
	writeFile(t, filepath.Join(home, ".ssh", "known_hosts"),
		hashedKnownHostsLine(t, "10.66.0.10", curry)+hashedKnownHostsLine(t, "elsewhere.example", stranger))

	r, deps := LoadDestinationNames(home)
	cfp := ssh.FingerprintSHA256(curry)
	sfp := ssh.FingerprintSHA256(stranger)
	if got := r.Resolve(cfp); got != "curry" {
		t.Errorf("hashed curry resolved to %q", got)
	}
	if !r.IsKnown(cfp) || !r.IsKnown(sfp) {
		t.Error("hashed entries not known")
	}
	if got := r.Resolve(sfp); got != "" {
		t.Errorf("unmatched hashed entry named %q", got)
	}
	if len(deps) == 0 {
		t.Error("no dependency files")
	}
}

func TestLearnedNamesPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "learned-hosts")
	l := LoadLearnedNames(path)
	l.Learn("SHA256:abc", "root@build.example.org")
	l.Learn("SHA256:bad", "evil host\nSHA256:x y")
	if l.Lookup("SHA256:abc") != "build.example.org" {
		t.Fatalf("lookup %q", l.Lookup("SHA256:abc"))
	}
	if l.Lookup("SHA256:bad") != "" {
		t.Fatal("invalid name learned")
	}
	reloaded := LoadLearnedNames(path)
	if reloaded.Lookup("SHA256:abc") != "build.example.org" {
		t.Fatal("learned name lost on reload")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("learned file mode: %v %v", err, info)
	}
}

func TestLearnedNameUsedForForwardedHop(t *testing.T) {
	host := testSigner(t)
	fp := ssh.FingerprintSHA256(host.PublicKey())
	dir := t.TempDir()
	khPath := filepath.Join(dir, "known_hosts")
	writeFile(t, khPath, hashedKnownHostsLine(t, "build.example.org", host.PublicKey()))
	resolver := NewKnownHostsResolver(khPath)

	saved := learnedNames
	learnedNames = LoadLearnedNames(filepath.Join(dir, "learned-hosts"))
	defer func() { learnedNames = saved }()

	// Direct login from grover names the hashed key.
	direct := &ProxyAgent{
		upstream:   &stubExtendedAgent{agent.NewKeyring()},
		caller:     &CallerContext{Name: "ssh", SSHDest: "tavis@build.example.org", Env: map[string]string{}},
		knownHosts: resolver,
	}
	if _, err := direct.Extension("session-bind@openssh.com", makeSignedSessionBind(t, host, []byte("direct-"+t.Name()), false)); err != nil {
		t.Fatal(err)
	}
	if learnedNames.Lookup(fp) != "build.example.org" {
		t.Fatalf("not learned: %q", learnedNames.Lookup(fp))
	}

	// Later, after a restart (fresh session cache), a second hop from a
	// remote host to the same key: no carry-over, but the learned name.
	savedSessions := sessionNames
	sessionNames = newSessionNameCache(256)
	defer func() { sessionNames = savedSessions }()
	hop := &ProxyAgent{
		upstream:   &stubExtendedAgent{agent.NewKeyring()},
		caller:     &CallerContext{Name: "ssh", SSHDest: "nano", Env: map[string]string{}},
		knownHosts: resolver,
	}
	first := testSigner(t)
	if _, err := hop.Extension("session-bind@openssh.com", makeSignedSessionBind(t, first, []byte("hop1-"+t.Name()), true)); err != nil {
		t.Fatal(err)
	}
	if _, err := hop.Extension("session-bind@openssh.com", makeSignedSessionBind(t, host, []byte("hop2-"+t.Name()), false)); err != nil {
		t.Fatal(err)
	}
	if got := hop.session.DestName(); got != "build.example.org" {
		t.Fatalf("second hop named %q", got)
	}
	if !hop.session.InKnownHosts() {
		t.Fatal("hashed key not known on second hop")
	}
}

func TestUnknownKeyNotLearned(t *testing.T) {
	host := testSigner(t)
	saved := learnedNames
	learnedNames = LoadLearnedNames(filepath.Join(t.TempDir(), "learned-hosts"))
	defer func() { learnedNames = saved }()
	p := &ProxyAgent{
		upstream:   &stubExtendedAgent{agent.NewKeyring()},
		caller:     &CallerContext{Name: "ssh", SSHDest: "github.com", Env: map[string]string{}},
		knownHosts: NewKnownHostsResolver(),
	}
	if _, err := p.Extension("session-bind@openssh.com", makeSignedSessionBind(t, host, []byte("x-"+t.Name()), false)); err != nil {
		t.Fatal(err)
	}
	if got := learnedNames.Lookup(ssh.FingerprintSHA256(host.PublicKey())); got != "" {
		t.Fatalf("key absent from known_hosts was learned as %q", got)
	}
}

func TestSignDestFingerprintFallback(t *testing.T) {
	ctx := &CallerContext{Name: "ssh"}
	unknown := &SessionBindInfo{DestKeyFingerprint: "SHA256:AbCdEfGhIjKlMn"}
	if got := SignDest(ctx, unknown); got != "unknown host SHA256:AbCdEfGh" {
		t.Errorf("unknown: %q", got)
	}
	unnamed := &SessionBindInfo{DestKeyFingerprint: "SHA256:AbCdEfGhIjKlMn", DestKnown: true}
	if got := SignDest(ctx, unnamed); got != "unnamed host SHA256:AbCdEfGh" {
		t.Errorf("unnamed: %q", got)
	}
	if got := fileSafeDest("unknown host SHA256:Ab/Cd"); strings.ContainsAny(got, " /:") {
		t.Errorf("file-safe dest %q", got)
	}
}
