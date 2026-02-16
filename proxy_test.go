package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

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
