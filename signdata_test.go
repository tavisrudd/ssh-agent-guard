package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type pamChallenge struct {
	cookieLen int
	user      string
	ruser     string
	service   string
	cwd       string
	argv      []string
	hostname  string
	ts        time.Time
}

func defaultPamChallenge() pamChallenge {
	return pamChallenge{
		cookieLen: 32,
		user:      "tavis",
		ruser:     "tavis",
		service:   "sudo",
		cwd:       "/home/tavis",
		argv:      []string{"sudo", "true"},
		hostname:  "or3",
		ts:        time.Now(),
	}
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// makePamData builds sign data the way pam_ssh_agent_auth 0.10.4 does.
func makePamData(c pamChallenge, key ssh.PublicKey) []byte {
	sid := u32(pamAgentAuthRequestV1)
	sid = append(sid, makeSSHString(make([]byte, c.cookieLen))...)
	for _, s := range []string{c.user, c.ruser, c.service, c.cwd} {
		sid = append(sid, makeSSHString([]byte(s))...)
	}
	var action []byte
	if c.argv != nil {
		action = u32(uint32(len(c.argv)))
		for _, a := range c.argv {
			action = append(action, makeSSHString([]byte(a))...)
		}
	}
	sid = append(sid, makeSSHString(action)...)
	sid = append(sid, makeSSHString([]byte(c.hostname))...)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(c.ts.Unix()))
	sid = append(sid, ts...)

	data := makeSSHString(sid)
	data = append(data, sshMsgUserauthTrustReq)
	data = append(data, makeSSHString([]byte(c.ruser))...)
	data = append(data, makeSSHString([]byte(pamAgentAuthServiceString))...)
	data = append(data, makeSSHString([]byte("publickey"))...)
	data = append(data, 1)
	data = append(data, makeSSHString([]byte(key.Type()))...)
	data = append(data, makeSSHString(key.Marshal())...)
	return data
}

func testSigner(t testing.TB) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestParsePamAgentAuthSignData(t *testing.T) {
	user := testSigner(t)
	c := defaultPamChallenge()
	req, err := parsePamAgentAuthSignData(makePamData(c, user.PublicKey()), user.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if req.Service != "sudo" || req.User != "tavis" || req.RUser != "tavis" || req.Hostname != "or3" || req.CWD != "/home/tavis" {
		t.Fatalf("fields: %+v", req)
	}
	if req.Command() != "sudo true" {
		t.Fatalf("command %q", req.Command())
	}
	nix := c
	nix.argv = []string{"/nix/store/abc-sudo-1.9/bin/sudo", "-i"}
	nreq, err := parsePamAgentAuthSignData(makePamData(nix, user.PublicKey()), user.PublicKey())
	if err != nil || nreq.Command() != "sudo -i" || nreq.Argv[0] != nix.argv[0] {
		t.Fatalf("store-path argv0: %v %q", err, nreq.Command())
	}
	if req.Timestamp.Unix() != c.ts.Unix() {
		t.Fatalf("timestamp %v", req.Timestamp)
	}
	label := (&SignRequest{Kind: SignKindPam, Pam: req}).Label()
	if label != "sudo@or3: sudo true" {
		t.Fatalf("label %q", label)
	}

	// Command line unavailable: empty action.
	c.argv = nil
	req, err = parsePamAgentAuthSignData(makePamData(c, user.PublicKey()), user.PublicKey())
	if err != nil || req.Argv != nil || req.Command() != "" {
		t.Fatalf("empty action: %v %+v", err, req)
	}
}

func TestParsePamAgentAuthSignDataRejects(t *testing.T) {
	user := testSigner(t)
	other := testSigner(t)
	good := makePamData(defaultPamChallenge(), user.PublicKey())

	// Userauth data is simply not a pam challenge.
	ua := makeUserauthData([]byte("sid"), user.PublicKey(), nil, false)
	if _, err := parsePamAgentAuthSignData(ua, user.PublicKey()); !errors.Is(err, errNotPamChallenge) {
		t.Fatalf("userauth data: %v", err)
	}
	if _, err := parsePamAgentAuthSignData([]byte("SSHSIG"), user.PublicKey()); !errors.Is(err, errNotPamChallenge) {
		t.Fatalf("sshsig: %v", err)
	}

	cases := map[string][]byte{
		"wrong key": makePamData(defaultPamChallenge(), other.PublicKey()),
		"trailing":  append(append([]byte(nil), good...), 0),
		"truncated": good[:len(good)-1],
		"short cookie": func() []byte {
			c := defaultPamChallenge()
			c.cookieLen = 8
			return makePamData(c, user.PublicKey())
		}(),
		"too many args": func() []byte {
			c := defaultPamChallenge()
			c.argv = make([]string, 300)
			return makePamData(c, user.PublicKey())
		}(),
	}
	for name, data := range cases {
		if _, err := parsePamAgentAuthSignData(data, user.PublicKey()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// Header ruser must equal body ruser.
	c := defaultPamChallenge()
	data := makePamData(c, user.PublicKey())
	c2 := c
	c2.ruser = "mallory"
	mixed := makePamData(c2, user.PublicKey())
	// splice: body from c, header from c2
	sidC, restC, _ := readSSHString(data)
	_, restC2, _ := readSSHString(mixed)
	_ = restC
	spliced := append(makeSSHString(sidC), restC2...)
	if _, err := parsePamAgentAuthSignData(spliced, user.PublicKey()); err == nil {
		t.Error("ruser mismatch accepted")
	}
}

func TestSanitizeDisplay(t *testing.T) {
	if got := sanitizeDisplay("a\nb\x1b[31mc", 64); got != "a?b?[31mc" {
		t.Fatalf("got %q", got)
	}
	if got := sanitizeDisplay(strings.Repeat("x", 10), 4); got != "xxxx…" {
		t.Fatalf("got %q", got)
	}
}

func TestSameHost(t *testing.T) {
	for _, tc := range []struct {
		claimed, dest string
		want          bool
	}{
		{"or3", "or3.lan", true},
		{"OR3", "root@or3.lan", true},
		{"or3.lan", "or3", true},
		{"or4", "or3.lan", false},
		{"", "or3", false},
		{"or3", "", false},
	} {
		if got := sameHost(tc.claimed, tc.dest); got != tc.want {
			t.Errorf("sameHost(%q, %q) = %v", tc.claimed, tc.dest, got)
		}
	}
}

// forwardedPamProxy returns a proxy whose connection carries a forwarding
// binding for host, named via the session carry-over from an earlier
// authenticating connection for the same session.
func forwardedPamProxy(t *testing.T, host ssh.Signer, sessionID []byte, name string) *ProxyAgent {
	t.Helper()
	auth := &ProxyAgent{
		upstream: &stubExtendedAgent{agent.NewKeyring()},
		caller:   &CallerContext{Name: "ssh", SSHDest: name, Env: map[string]string{}},
	}
	if _, err := auth.Extension("session-bind@openssh.com", makeSignedSessionBind(t, host, sessionID, false)); err != nil {
		t.Fatal(err)
	}
	fwd := &ProxyAgent{
		upstream: &stubExtendedAgent{agent.NewKeyring()},
		caller:   &CallerContext{Name: "ssh:", Env: map[string]string{}},
	}
	if _, err := fwd.Extension("session-bind@openssh.com", makeSignedSessionBind(t, host, sessionID, true)); err != nil {
		t.Fatal(err)
	}
	return fwd
}

func TestForwardedPamClassification(t *testing.T) {
	host := testSigner(t)
	user := testSigner(t)
	sid := []byte("or3-session-" + t.Name())
	p := forwardedPamProxy(t, host, sid, "root@or3.lan")
	if got := p.session.DestName(); got != "or3.lan" {
		t.Fatalf("carried-over name %q", got)
	}
	if p.session.DestHostname != "" {
		t.Fatal("carry-over must not pretend to be a known_hosts name")
	}

	now := time.Now()
	req, err := p.classifySignRequest(makePamData(defaultPamChallenge(), user.PublicKey()), user.PublicKey(), now)
	if err != nil {
		t.Fatalf("genuine forwarded sudo rejected: %v", err)
	}
	if req.Kind != SignKindPam || req.Pam.Service != "sudo" {
		t.Fatalf("classified as %+v", req)
	}

	ruleOf := func(err error) string {
		var sve *signValidationError
		if errors.As(err, &sve) {
			return sve.rule
		}
		return ""
	}

	relayed := defaultPamChallenge()
	relayed.hostname = "grover"
	if _, err := p.classifySignRequest(makePamData(relayed, user.PublicKey()), user.PublicKey(), now); ruleOf(err) != "pam-host-mismatch" {
		t.Fatalf("relayed challenge: %v", err)
	}

	stale := defaultPamChallenge()
	stale.ts = now.Add(-10 * time.Minute)
	if _, err := p.classifySignRequest(makePamData(stale, user.PublicKey()), user.PublicKey(), now); ruleOf(err) != "pam-stale" {
		t.Fatalf("stale challenge: %v", err)
	}

	// Arbitrary data on a forwarded chain is still refused.
	if _, err := p.classifySignRequest([]byte("anything"), user.PublicKey(), now); err == nil || !strings.Contains(err.Error(), "forwarding") {
		t.Fatalf("arbitrary data: %v", err)
	}
	// So is a userauth request.
	ua := makeUserauthData(sid, user.PublicKey(), host.PublicKey(), true)
	if _, err := p.classifySignRequest(ua, user.PublicKey(), now); err == nil {
		t.Fatal("userauth on a forwarding-final chain accepted")
	}
}

func TestForwardedPamUnknownDestFailsClosed(t *testing.T) {
	host := testSigner(t)
	user := testSigner(t)
	p := &ProxyAgent{
		upstream: &stubExtendedAgent{agent.NewKeyring()},
		caller:   &CallerContext{Name: "ssh:", Env: map[string]string{}},
	}
	if _, err := p.Extension("session-bind@openssh.com", makeSignedSessionBind(t, host, []byte("never-authenticated-"+t.Name()), true)); err != nil {
		t.Fatal(err)
	}
	_, err := p.classifySignRequest(makePamData(defaultPamChallenge(), user.PublicKey()), user.PublicKey(), time.Now())
	var sve *signValidationError
	if !errors.As(err, &sve) || sve.rule != "pam-dest-unknown" {
		t.Fatalf("unknown destination: %v", err)
	}
}

func TestSessionNameCarryOverRequiresSameHostKey(t *testing.T) {
	host := testSigner(t)
	impostor := testSigner(t)
	sid := []byte("shared-session-" + t.Name())
	_ = forwardedPamProxy(t, host, sid, "or3.lan")
	p := &ProxyAgent{
		upstream: &stubExtendedAgent{agent.NewKeyring()},
		caller:   &CallerContext{Name: "ssh:", Env: map[string]string{}},
	}
	if _, err := p.Extension("session-bind@openssh.com", makeSignedSessionBind(t, impostor, sid, true)); err != nil {
		t.Fatal(err)
	}
	if p.session.DestName() != "" {
		t.Fatalf("impostor host key inherited name %q", p.session.DestName())
	}
}

func TestSessionNameCacheBounded(t *testing.T) {
	c := newSessionNameCache(2)
	c.Remember([]byte("a"), []byte("k"), "a.example")
	c.Remember([]byte("b"), []byte("k"), "b.example")
	c.Remember([]byte("c"), []byte("k"), "c.example")
	if c.Lookup([]byte("a"), []byte("k")) != "" {
		t.Fatal("oldest entry not evicted")
	}
	if c.Lookup([]byte("c"), []byte("k")) != "c.example" {
		t.Fatal("newest entry missing")
	}
}

func TestLocalPamAndOtherClassification(t *testing.T) {
	user := testSigner(t)
	p := &ProxyAgent{
		upstream: &stubExtendedAgent{agent.NewKeyring()},
		caller:   &CallerContext{Name: "sudo", Env: map[string]string{}},
	}
	req, err := p.classifySignRequest(makePamData(defaultPamChallenge(), user.PublicKey()), user.PublicKey(), time.Now())
	if err != nil || req.Kind != SignKindPam {
		t.Fatalf("local pam: %v %+v", err, req)
	}
	req, err = p.classifySignRequest([]byte("SSHSIG..."), user.PublicKey(), time.Now())
	if err != nil || req.Kind != SignKindOther {
		t.Fatalf("local other: %v %+v", err, req)
	}
}

func TestPolicyPamOptIn(t *testing.T) {
	policy := newTestPolicy(t, `
default_action: allow
rules:
  - name: sudo-or3
    match:
      sign_kind: pam
      pam_service: sudo
      is_forwarded: true
      ssh_dest: "or3*"
    action: confirm
  - name: pam-elsewhere
    match:
      sign_kind: pam
    action: deny
  - name: forwarded-any
    match:
      is_forwarded: true
    action: allow
`)
	ctx := &CallerContext{Name: "ssh:", Env: map[string]string{}}
	or3 := &SessionBindInfo{IsForwarded: true, DestAlias: "or3.lan"}
	other := &SessionBindInfo{IsForwarded: true, DestAlias: "nano"}
	pam := &SignRequest{Kind: SignKindPam, Pam: &PamRequest{Service: "sudo", Hostname: "or3"}}

	if r := policy.EvaluateRequest(ctx, or3, "SHA256:x", pam); r.Action != Confirm || r.RuleName != "sudo-or3" {
		t.Fatalf("sudo on or3: %+v", r)
	}
	if r := policy.EvaluateRequest(ctx, other, "SHA256:x", pam); r.Action != Deny || r.RuleName != "pam-elsewhere" {
		t.Fatalf("sudo elsewhere: %+v", r)
	}
	// Userauth on a forwarded chain is unaffected by the pam rules.
	if r := policy.EvaluateRequest(ctx, other, "SHA256:x", &SignRequest{Kind: SignKindUserauth}); r.RuleName != "forwarded-any" {
		t.Fatalf("userauth: %+v", r)
	}

	// Without any sign_kind: pam rule, broad rules never approve pam.
	legacy := newTestPolicy(t, `
default_action: allow
rules:
  - name: forwarded-any
    match:
      is_forwarded: true
    action: allow
`)
	if r := legacy.EvaluateRequest(ctx, or3, "SHA256:x", pam); r.Action != Deny || r.RuleName != "default-pam" {
		t.Fatalf("legacy policy approved pam: %+v", r)
	}
}

func TestPolicyPamFieldsRequireSignKind(t *testing.T) {
	_, err := compileMatch(MatchSpec{PamService: "sudo"})
	if err == nil {
		t.Fatal("pam_service without sign_kind: pam accepted")
	}
	_, err = compileMatch(MatchSpec{SignKind: "sudo"})
	if err == nil {
		t.Fatal("invalid sign_kind accepted")
	}
}

func FuzzParsePamAgentAuthSignData(f *testing.F) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	f.Add(makePamData(defaultPamChallenge(), signer.PublicKey()))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parsePamAgentAuthSignData(data, signer.PublicKey())
	})
}

func TestProxyForwardedSudoEndToEnd(t *testing.T) {
	_, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: userPriv}); err != nil {
		t.Fatal(err)
	}
	userSigner, _ := ssh.NewSignerFromKey(userPriv)
	host := testSigner(t)
	sid := []byte("e2e-" + t.Name())
	_ = forwardedPamProxy(t, host, sid, "or3.lan")

	policy := newTestPolicy(t, `
default_action: deny
rules:
  - name: sudo-or3
    match:
      sign_kind: pam
      pam_service: sudo
      ssh_dest: "or3*"
    action: allow
`)
	stateDir := t.TempDir()
	p := &ProxyAgent{
		upstream:   &stubExtendedAgent{keyring},
		caller:     &CallerContext{Name: "ssh:", Env: map[string]string{}},
		logger:     NewLogger(stateDir, policy),
		policy:     policy,
		confirmCfg: &ConfirmConfig{},
	}
	if _, err := p.Extension("session-bind@openssh.com", makeSignedSessionBind(t, host, sid, true)); err != nil {
		t.Fatal(err)
	}
	data := makePamData(defaultPamChallenge(), userSigner.PublicKey())
	sig, err := p.SignWithFlags(userSigner.PublicKey(), data, 0)
	if err != nil {
		t.Fatalf("forwarded sudo denied: %v", err)
	}
	if err := userSigner.PublicKey().Verify(data, sig); err != nil {
		t.Fatal(err)
	}

	relayed := defaultPamChallenge()
	relayed.hostname = "nano"
	if _, err := p.SignWithFlags(userSigner.PublicKey(), makePamData(relayed, userSigner.PublicKey()), 0); err == nil {
		t.Fatal("relayed challenge signed")
	}

	entries, _ := os.ReadDir(stateDir)
	var allowLog string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), "-allow.yaml") {
			b, _ := os.ReadFile(filepath.Join(stateDir, e.Name()))
			allowLog = string(b)
		}
	}
	for _, want := range []string{"sign_kind: pam", "service: sudo", "host: or3", "host_matches_dest: true", "rule: sudo-or3"} {
		if !strings.Contains(allowLog, want) {
			t.Errorf("allow log lacks %q:\n%s", want, allowLog)
		}
	}
}
