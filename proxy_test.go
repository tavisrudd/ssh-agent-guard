package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// stubExtendedAgent wraps an agent.Agent to implement ExtendedAgent.
// Extension returns ErrExtensionUnsupported, which is sufficient for tests
// that only need the proxy to process session-bind before forwarding.
type stubExtendedAgent struct {
	agent.Agent
}

func (s *stubExtendedAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

func (s *stubExtendedAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	return s.Agent.Sign(key, data)
}

// testProxy sets up a full proxy pipeline: upstream keyring agent listening on
// a Unix socket, the ProxyAgent wired between client and upstream. Returns a
// client connected through the proxy, and a cleanup function.
func testProxy(t *testing.T, policy *Policy) (agent.ExtendedAgent, func()) {
	t.Helper()
	dir := t.TempDir()

	// Generate a test key and add it to a keyring agent
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}

	// Start upstream agent on a Unix socket
	upstreamPath := filepath.Join(dir, "upstream.sock")
	upstreamListener, err := net.Listen("unix", upstreamPath)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := upstreamListener.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(keyring, conn)
		}
	}()

	// Start proxy agent on a Unix socket
	proxyPath := filepath.Join(dir, "proxy.sock")
	proxyListener, err := net.Listen("unix", proxyPath)
	if err != nil {
		t.Fatal(err)
	}

	logger := NewLogger(filepath.Join(dir, "state"), policy)

	go func() {
		for {
			conn, err := proxyListener.Accept()
			if err != nil {
				return
			}
			go handleConnection(conn, upstreamPath, logger, nil, policy, &ConfirmConfig{})
		}
	}()

	// Connect a client through the proxy
	clientConn, err := net.Dial("unix", proxyPath)
	if err != nil {
		t.Fatal(err)
	}
	client := agent.NewClient(clientConn)

	cleanup := func() {
		clientConn.Close()
		proxyListener.Close()
		upstreamListener.Close()
	}

	return client, cleanup
}

// newTestPolicy creates a Policy from a YAML string.
func newTestPolicy(t *testing.T, yaml string) *Policy {
	t.Helper()
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyFile, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	policy, _ := NewPolicy(policyFile)
	return policy
}

func TestProxyListKeys(t *testing.T) {
	policy := newTestPolicy(t, "default_action: allow\nrules: []\n")
	client, cleanup := testProxy(t, policy)
	defer cleanup()

	keys, err := client.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
}

func TestProxySignAllowed(t *testing.T) {
	policy := newTestPolicy(t, "default_action: allow\nrules: []\n")
	client, cleanup := testProxy(t, policy)
	defer cleanup()

	keys, err := client.List()
	if err != nil {
		t.Fatal(err)
	}

	// Sign some data
	data := []byte("test data to sign")
	sig, err := client.Sign(keys[0], data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify the signature is valid
	pubKey, err := ssh.ParsePublicKey(keys[0].Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if err := pubKey.Verify(data, sig); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

func TestProxySignDenied(t *testing.T) {
	policy := newTestPolicy(t, "default_action: deny\nrules: []\n")
	client, cleanup := testProxy(t, policy)
	defer cleanup()

	keys, err := client.List()
	if err != nil {
		t.Fatal(err)
	}

	// Sign should fail with deny policy
	_, err = client.Sign(keys[0], []byte("test"))
	if err == nil {
		t.Fatal("expected Sign to fail with deny policy")
	}
}

func TestProxySignWithPolicyRules(t *testing.T) {
	// Allow only from specific callers, deny everything else.
	// Since the test process won't match "ssh", signing should be denied.
	policy := newTestPolicy(t, `
default_action: deny
rules:
  - name: allow-ssh
    match:
      process_name: ssh
    action: allow
`)
	client, cleanup := testProxy(t, policy)
	defer cleanup()

	keys, err := client.List()
	if err != nil {
		t.Fatal(err)
	}

	// Our test process name won't be "ssh", so this should be denied
	_, err = client.Sign(keys[0], []byte("test"))
	if err == nil {
		t.Fatal("expected Sign to fail — caller is not 'ssh'")
	}
}

func TestProxyBlocksMutations(t *testing.T) {
	policy := newTestPolicy(t, "default_action: allow\nrules: []\n")
	client, cleanup := testProxy(t, policy)
	defer cleanup()

	// Add should be blocked
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	err := client.Add(agent.AddedKey{PrivateKey: priv})
	if err == nil {
		t.Error("expected Add to be blocked")
	}

	// RemoveAll should be blocked
	err = client.RemoveAll()
	if err == nil {
		t.Error("expected RemoveAll to be blocked")
	}

	// Lock should be blocked
	err = client.Lock([]byte("passphrase"))
	if err == nil {
		t.Error("expected Lock to be blocked")
	}

	// Unlock should be blocked
	err = client.Unlock([]byte("passphrase"))
	if err == nil {
		t.Error("expected Unlock to be blocked")
	}

	// Keys should still be listable after blocked mutations
	keys, err := client.List()
	if err != nil {
		t.Fatalf("List after mutations: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key after blocked mutations, got %d", len(keys))
	}
}

func TestProxySessionBind(t *testing.T) {
	policy := newTestPolicy(t, `
default_action: allow
rules:
  - name: deny-forwarded
    match:
      is_forwarded: true
    action: deny
`)
	client, cleanup := testProxy(t, policy)
	defer cleanup()

	// Build a session-bind extension message
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	hostKeyBlob := hostSigner.PublicKey().Marshal()

	var payload []byte
	payload = append(payload, makeSSHString(hostKeyBlob)...)
	payload = append(payload, makeSSHString([]byte("session-id"))...)
	payload = append(payload, makeSSHString([]byte("signature"))...)
	payload = append(payload, 0x01) // forwarded=true

	// Send session-bind — should be forwarded to upstream
	// The upstream keyring doesn't implement Extension, so this returns
	// agent.ErrExtensionUnsupported or similar, but the proxy should
	// still capture the session info.
	client.(agent.ExtendedAgent).Extension("session-bind@openssh.com", payload)

	// Now signing should be denied because policy denies forwarded sessions
	keys, err := client.List()
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Sign(keys[0], []byte("test"))
	if err == nil {
		t.Fatal("expected Sign to fail for forwarded session")
	}
}

func TestProxySessionBindMalformedFailsClosed(t *testing.T) {
	// When session-bind is present but unparseable, the proxy should treat
	// it as forwarded (fail closed) so that is_forwarded deny rules still fire.
	policy := newTestPolicy(t, `
default_action: allow
rules:
  - name: deny-forwarded
    match:
      is_forwarded: true
    action: deny
`)
	client, cleanup := testProxy(t, policy)
	defer cleanup()

	// Send a malformed session-bind (truncated payload)
	client.(agent.ExtendedAgent).Extension("session-bind@openssh.com", []byte{0, 0, 0, 5, 1, 2, 3})

	// Signing should be denied because malformed session-bind is treated as forwarded
	keys, err := client.List()
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Sign(keys[0], []byte("test"))
	if err == nil {
		t.Fatal("expected Sign to fail — malformed session-bind should be treated as forwarded")
	}
}

func TestSessionBindForwardedMovesSSHDestToForwardedVia(t *testing.T) {
	// When session-bind says forwarded, the local SSH cmdline destination
	// is the intermediate host. It should be moved to ForwardedVia so that
	// ssh_dest falls through to session-bind's DestHostname.
	caller := &CallerContext{
		Name:    "ssh",
		SSHDest: "bastion.example.com",
		Env:     map[string]string{},
	}

	proxy := &ProxyAgent{
		upstream: &stubExtendedAgent{agent.NewKeyring()},
		caller:   caller,
	}

	// Build forwarded session-bind
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	hostKeyBlob := hostSigner.PublicKey().Marshal()

	var payload []byte
	payload = append(payload, makeSSHString(hostKeyBlob)...)
	payload = append(payload, makeSSHString([]byte("session-id"))...)
	payload = append(payload, makeSSHString([]byte("signature"))...)
	payload = append(payload, 0x01) // forwarded=true

	proxy.Extension("session-bind@openssh.com", payload)

	if caller.SSHDest != "" {
		t.Errorf("SSHDest should be cleared after forwarded session-bind, got %q", caller.SSHDest)
	}
	if caller.ForwardedVia != "bastion.example.com" {
		t.Errorf("ForwardedVia should be bastion.example.com, got %q", caller.ForwardedVia)
	}
	if proxy.session == nil || !proxy.session.IsForwarded {
		t.Error("session should be set and forwarded")
	}
}

func TestSessionBindNotForwardedKeepsSSHDest(t *testing.T) {
	// When session-bind says NOT forwarded, SSHDest should stay — it's the
	// actual destination (same as session-bind's DestHostname).
	caller := &CallerContext{
		Name:    "ssh",
		SSHDest: "target.example.com",
		Env:     map[string]string{},
	}

	proxy := &ProxyAgent{
		upstream: &stubExtendedAgent{agent.NewKeyring()},
		caller:   caller,
	}

	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	hostKeyBlob := hostSigner.PublicKey().Marshal()

	var payload []byte
	payload = append(payload, makeSSHString(hostKeyBlob)...)
	payload = append(payload, makeSSHString([]byte("session-id"))...)
	payload = append(payload, makeSSHString([]byte("signature"))...)
	payload = append(payload, 0x00) // forwarded=false

	proxy.Extension("session-bind@openssh.com", payload)

	if caller.SSHDest != "target.example.com" {
		t.Errorf("SSHDest should be unchanged, got %q", caller.SSHDest)
	}
	if caller.ForwardedVia != "" {
		t.Errorf("ForwardedVia should be empty, got %q", caller.ForwardedVia)
	}
}

func TestSessionBindMalformedMovesSSHDestToForwardedVia(t *testing.T) {
	// Malformed session-bind is treated as forwarded (fail closed).
	// SSHDest should still be moved to ForwardedVia.
	caller := &CallerContext{
		Name:    "ssh",
		SSHDest: "bastion.example.com",
		Env:     map[string]string{},
	}

	proxy := &ProxyAgent{
		upstream: &stubExtendedAgent{agent.NewKeyring()},
		caller:   caller,
	}

	// Truncated payload → parse error → treated as forwarded
	proxy.Extension("session-bind@openssh.com", []byte{0, 0, 0, 5, 1, 2, 3})

	if caller.SSHDest != "" {
		t.Errorf("SSHDest should be cleared, got %q", caller.SSHDest)
	}
	if caller.ForwardedVia != "bastion.example.com" {
		t.Errorf("ForwardedVia should be bastion.example.com, got %q", caller.ForwardedVia)
	}
}

func TestConfirmRateLimited(t *testing.T) {
	// Policy that requires confirmation for all sign requests.
	// With no YubiKey available, confirmation would normally fail with
	// method=missing. But with rate limiting, requests beyond max_pending
	// should be denied immediately before even checking for a YubiKey.
	policy := newTestPolicy(t, "default_action: confirm\nrules: []\n")
	dir := t.TempDir()

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyring := agent.NewKeyring()
	keyring.Add(agent.AddedKey{PrivateKey: priv})

	upstreamPath := filepath.Join(dir, "upstream.sock")
	upstreamListener, _ := net.Listen("unix", upstreamPath)
	go func() {
		for {
			conn, err := upstreamListener.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(keyring, conn)
		}
	}()
	defer upstreamListener.Close()

	proxyPath := filepath.Join(dir, "proxy.sock")
	proxyListener, _ := net.Listen("unix", proxyPath)
	stateDir := filepath.Join(dir, "state")
	logger := NewLogger(stateDir, policy)

	confirmCfg := &ConfirmConfig{MaxPending: 1}
	go func() {
		for {
			conn, err := proxyListener.Accept()
			if err != nil {
				return
			}
			go handleConnection(conn, upstreamPath, logger, nil, policy, confirmCfg)
		}
	}()
	defer proxyListener.Close()

	// Simulate one already-pending confirmation
	pendingConfirms.Store(1)
	t.Cleanup(func() { pendingConfirms.Store(0) })

	clientConn, _ := net.Dial("unix", proxyPath)
	defer clientConn.Close()
	client := agent.NewClient(clientConn)

	keys, err := client.List()
	if err != nil {
		t.Fatal(err)
	}

	// Sign should be denied — counter is at 1 and max is 1
	_, err = client.Sign(keys[0], []byte("test"))
	if err == nil {
		t.Fatal("expected Sign to fail when rate-limited")
	}

	// Counter should still be 1 (not 2 — the rate-limited request decremented)
	if n := pendingConfirms.Load(); n != 1 {
		t.Errorf("expected pendingConfirms=1, got %d", n)
	}

	// Verify the log file records the rate limiting
	time.Sleep(100 * time.Millisecond)
	entries, _ := os.ReadDir(stateDir)
	foundRateLimited := false
	for _, e := range entries {
		if e.Name() == "current.yaml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(stateDir, e.Name()))
		if err != nil {
			continue
		}
		if strings.Contains(string(data), "rate-limited") {
			foundRateLimited = true
		}
	}
	if !foundRateLimited {
		t.Error("expected a log file with confirm_method: rate-limited")
	}
}

func TestConfirmRateLimitAllowsUnderMax(t *testing.T) {
	// With max_pending: 2 and 0 pending, a confirm request should NOT be
	// rate-limited. It will still fail (no YubiKey) but via a different path.
	policy := newTestPolicy(t, "default_action: confirm\nrules: []\n")
	dir := t.TempDir()

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyring := agent.NewKeyring()
	keyring.Add(agent.AddedKey{PrivateKey: priv})

	upstreamPath := filepath.Join(dir, "upstream.sock")
	upstreamListener, _ := net.Listen("unix", upstreamPath)
	go func() {
		for {
			conn, err := upstreamListener.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(keyring, conn)
		}
	}()
	defer upstreamListener.Close()

	proxyPath := filepath.Join(dir, "proxy.sock")
	proxyListener, _ := net.Listen("unix", proxyPath)
	stateDir := filepath.Join(dir, "state")
	logger := NewLogger(stateDir, policy)

	confirmCfg := &ConfirmConfig{MaxPending: 2}
	go func() {
		for {
			conn, err := proxyListener.Accept()
			if err != nil {
				return
			}
			go handleConnection(conn, upstreamPath, logger, nil, policy, confirmCfg)
		}
	}()
	defer proxyListener.Close()

	// Start with 0 pending
	pendingConfirms.Store(0)
	t.Cleanup(func() { pendingConfirms.Store(0) })

	clientConn, _ := net.Dial("unix", proxyPath)
	defer clientConn.Close()
	client := agent.NewClient(clientConn)

	keys, err := client.List()
	if err != nil {
		t.Fatal(err)
	}

	// Sign will still fail (no YubiKey), but it should NOT be rate-limited.
	// The confirm attempt proceeds, fails with method=missing, and the counter
	// should be back to 0 after the request completes.
	_, _ = client.Sign(keys[0], []byte("test"))

	time.Sleep(100 * time.Millisecond)
	if n := pendingConfirms.Load(); n != 0 {
		t.Errorf("expected pendingConfirms=0 after completed request, got %d", n)
	}

	// Verify the log does NOT show rate-limited
	entries, _ := os.ReadDir(stateDir)
	for _, e := range entries {
		if e.Name() == "current.yaml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(stateDir, e.Name()))
		if err != nil {
			continue
		}
		if strings.Contains(string(data), "rate-limited") {
			t.Error("should not be rate-limited when under max")
		}
	}
}

func TestProxyLogWritten(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	os.WriteFile(policyFile, []byte("default_action: allow\nrules: []\n"), 0644)
	policy, _ := NewPolicy(policyFile)

	stateDir := filepath.Join(dir, "state")
	logger := NewLogger(stateDir, policy)

	// Generate key and upstream
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyring := agent.NewKeyring()
	keyring.Add(agent.AddedKey{PrivateKey: priv})

	upstreamPath := filepath.Join(dir, "upstream.sock")
	upstreamListener, _ := net.Listen("unix", upstreamPath)
	go func() {
		for {
			conn, err := upstreamListener.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(keyring, conn)
		}
	}()
	defer upstreamListener.Close()

	proxyPath := filepath.Join(dir, "proxy.sock")
	proxyListener, _ := net.Listen("unix", proxyPath)
	go func() {
		for {
			conn, err := proxyListener.Accept()
			if err != nil {
				return
			}
			go handleConnection(conn, upstreamPath, logger, nil, policy, &ConfirmConfig{})
		}
	}()
	defer proxyListener.Close()

	clientConn, _ := net.Dial("unix", proxyPath)
	client := agent.NewClient(clientConn)
	defer clientConn.Close()

	keys, _ := client.List()
	client.Sign(keys[0], []byte("test"))

	// Give the async logger time to write
	time.Sleep(100 * time.Millisecond)

	// Check that a YAML log file was written
	entries, _ := os.ReadDir(stateDir)
	foundLog := false
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".yaml" && e.Name() != "current.yaml" {
			foundLog = true
		}
	}
	if !foundLog {
		t.Error("expected a YAML log file to be written after sign")
	}
}
