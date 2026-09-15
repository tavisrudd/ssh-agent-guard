package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// makeSSHString creates a uint32-length-prefixed byte string (SSH wire format).
func makeSSHString(data []byte) []byte {
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(data)))
	copy(buf[4:], data)
	return buf
}

func makeSignedSessionBind(t testing.TB, signer ssh.Signer, sessionID []byte, forwarded bool) []byte {
	t.Helper()
	sig, err := signer.Sign(rand.Reader, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	payload := makeSSHString(signer.PublicKey().Marshal())
	payload = append(payload, makeSSHString(sessionID)...)
	payload = append(payload, makeSSHString(ssh.Marshal(sig))...)
	if forwarded {
		return append(payload, 1)
	}
	return append(payload, 0)
}

func makeUserauthData(sessionID []byte, userKey, hostKey ssh.PublicKey, hostbound bool) []byte {
	data := makeSSHString(sessionID)
	data = append(data, 50) // SSH2_MSG_USERAUTH_REQUEST
	data = append(data, makeSSHString([]byte("alice"))...)
	data = append(data, makeSSHString([]byte("ssh-connection"))...)
	method := "publickey"
	if hostbound {
		method = "publickey-hostbound-v00@openssh.com"
	}
	data = append(data, makeSSHString([]byte(method))...)
	data = append(data, 1) // signature follows
	data = append(data, makeSSHString([]byte(userKey.Type()))...)
	data = append(data, makeSSHString(userKey.Marshal())...)
	if hostbound {
		data = append(data, makeSSHString(hostKey.Marshal())...)
	}
	return data
}

func TestReadSSHString(t *testing.T) {
	// Normal string
	data := makeSSHString([]byte("hello"))
	s, rest, err := readSSHString(data)
	if err != nil {
		t.Fatal(err)
	}
	if string(s) != "hello" {
		t.Errorf("got %q, want hello", s)
	}
	if len(rest) != 0 {
		t.Errorf("rest should be empty, got %d bytes", len(rest))
	}

	// String with trailing data
	trailing := append(data, 0x42, 0x43)
	s, rest, err = readSSHString(trailing)
	if err != nil {
		t.Fatal(err)
	}
	if string(s) != "hello" {
		t.Errorf("got %q, want hello", s)
	}
	if len(rest) != 2 {
		t.Errorf("rest should be 2 bytes, got %d", len(rest))
	}

	// Too short for length
	_, _, err = readSSHString([]byte{0, 0})
	if err == nil {
		t.Error("expected error for short length")
	}

	// Length exceeds available data
	short := []byte{0, 0, 0, 10, 1, 2, 3}
	_, _, err = readSSHString(short)
	if err == nil {
		t.Error("expected error for truncated data")
	}

	// Empty string
	empty := makeSSHString(nil)
	s, _, err = readSSHString(empty)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 0 {
		t.Errorf("expected empty string, got %d bytes", len(s))
	}
}

func TestParseSessionBind(t *testing.T) {
	// Generate a real ed25519 key for the host key
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	expectedFP := ssh.FingerprintSHA256(signer.PublicKey())

	// Test not-forwarded
	notForwarded := makeSignedSessionBind(t, signer, []byte("session-id-here"), false)
	info, err := parseSessionBind(notForwarded)
	if err != nil {
		t.Fatal(err)
	}
	if info.DestKeyFingerprint != expectedFP {
		t.Errorf("fingerprint = %q, want %q", info.DestKeyFingerprint, expectedFP)
	}
	if info.IsForwarded {
		t.Error("expected not forwarded")
	}

	// Test forwarded
	forwarded := makeSignedSessionBind(t, signer, []byte("session-id-forwarded"), true)
	info, err = parseSessionBind(forwarded)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsForwarded {
		t.Error("expected forwarded")
	}

	// Test truncated payload
	_, err = parseSessionBind(notForwarded[:5])
	if err == nil {
		t.Error("expected error for truncated payload")
	}

	// Test missing forwarding flag
	_, err = parseSessionBind(notForwarded[:len(notForwarded)-1])
	if err == nil {
		t.Error("expected error for missing forwarding flag")
	}

	// The host key is public metadata; a forged signature must not be trusted.
	forged := append([]byte(nil), notForwarded...)
	forged[len(forged)-2] ^= 0x01
	if _, err = parseSessionBind(forged); err == nil {
		t.Error("expected error for forged signature")
	}
}

func TestParseSessionBindRejectsOversizeSessionID(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	payload := makeSignedSessionBind(t, signer, make([]byte, maxSessionIDBytes+1), true)
	if _, err := parseSessionBind(payload); err == nil {
		t.Fatal("oversize session identifier was accepted")
	}
}

func TestParseSessionBindRejectsOversizeHostCertificate(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cert := &ssh.Certificate{
		Key:         signer.PublicKey(),
		CertType:    ssh.HostCert,
		Reserved:    make([]byte, maxSessionBindBytes),
		ValidBefore: ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	certSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		t.Fatal(err)
	}
	payload := makeSignedSessionBind(t, certSigner, []byte("session-id"), true)
	if len(payload) <= maxSessionBindBytes {
		t.Fatalf("test payload is only %d bytes", len(payload))
	}
	if _, err := parseSessionBind(payload); err == nil {
		t.Fatal("oversize host certificate was accepted")
	}
}

func TestValidateSignatureTrailer(t *testing.T) {
	if err := validateSignatureTrailer(&ssh.Signature{Format: ssh.KeyAlgoED25519, Rest: []byte{1}}); err == nil {
		t.Fatal("ordinary signature trailer was accepted")
	}
	if err := validateSignatureTrailer(&ssh.Signature{Format: ssh.KeyAlgoSKED25519, Rest: make([]byte, 5)}); err != nil {
		t.Fatalf("valid security-key signature trailer rejected: %v", err)
	}
	if err := validateSignatureTrailer(&ssh.Signature{Format: ssh.KeyAlgoSKED25519, Rest: make([]byte, 4)}); err == nil {
		t.Fatal("invalid security-key signature trailer was accepted")
	}
}

func TestKnownHostsResolver(t *testing.T) {
	// Generate two keys
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	signer1, _ := ssh.NewSignerFromKey(priv1)
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	signer2, _ := ssh.NewSignerFromKey(priv2)

	fp1 := ssh.FingerprintSHA256(signer1.PublicKey())
	fp2 := ssh.FingerprintSHA256(signer2.PublicKey())

	// Build a known_hosts file
	authKey1 := ssh.MarshalAuthorizedKey(signer1.PublicKey())
	authKey2 := ssh.MarshalAuthorizedKey(signer2.PublicKey())

	content := "# comment line\n"
	// host1 has multiple names
	content += "host1.example.com,192.168.1.1 " + string(authKey1)
	// host2 uses [host]:port format
	content += "[host2.example.com]:2222 " + string(authKey2)
	// hashed entry (should be skipped)
	content += "|1|salt|hash ssh-ed25519 AAAA...\n"
	// @cert-authority (should be skipped)
	content += "@cert-authority *.example.com ssh-ed25519 AAAA...\n"

	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	os.WriteFile(path, []byte(content), 0644)

	resolver := NewKnownHostsResolver(path)

	// Should resolve host1 — shortest name wins
	resolved := resolver.Resolve(fp1)
	if resolved != "192.168.1.1" {
		t.Errorf("resolve fp1 = %q, want 192.168.1.1", resolved)
	}

	// Should resolve host2 (bracket stripped)
	resolved = resolver.Resolve(fp2)
	if resolved != "host2.example.com" {
		t.Errorf("resolve fp2 = %q, want host2.example.com", resolved)
	}

	// Unknown fingerprint
	resolved = resolver.Resolve("SHA256:unknown")
	if resolved != "" {
		t.Errorf("resolve unknown = %q, want empty", resolved)
	}
}

func TestKnownHostsResolverMissingFile(t *testing.T) {
	resolver := NewKnownHostsResolver("/nonexistent/known_hosts")
	if got := resolver.Resolve("SHA256:anything"); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestAppendUnique(t *testing.T) {
	s := appendUnique(nil, "a")
	s = appendUnique(s, "b")
	s = appendUnique(s, "a") // duplicate
	if len(s) != 2 {
		t.Errorf("expected 2 items, got %d: %v", len(s), s)
	}
}

// Fuzz tests for wire-format parsing. These exercise the SSH wire-format
// parser with arbitrary input to catch panics, OOB reads, and allocation bombs.

func FuzzReadSSHString(f *testing.F) {
	// Seed with valid and edge-case inputs
	f.Add(makeSSHString([]byte("hello")))
	f.Add(makeSSHString(nil))
	f.Add([]byte{0, 0})                   // too short
	f.Add([]byte{0, 0, 0, 10, 1, 2, 3})   // length exceeds data
	f.Add([]byte{0, 0, 0, 0})             // zero-length string
	f.Add([]byte{})                       // empty input
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}) // max uint32 length

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic. Errors are expected for malformed input.
		s, rest, err := readSSHString(data)
		if err != nil {
			return
		}
		// If successful, the string + rest should account for all input
		if len(s)+len(rest)+4 != len(data) {
			t.Errorf("length mismatch: string=%d rest=%d header=4 total=%d input=%d",
				len(s), len(rest), len(s)+len(rest)+4, len(data))
		}
	})
}

func FuzzParseSessionBind(f *testing.F) {
	// Seed with a valid payload
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	validPayload := makeSignedSessionBind(f, signer, []byte("session-id"), true)

	f.Add(validPayload)
	f.Add([]byte{})                           // empty
	f.Add([]byte{0, 0, 0, 5, 1, 2, 3, 4, 5})  // valid SSH string but not a valid key
	f.Add(validPayload[:len(validPayload)-1]) // missing forwarding flag
	f.Add(validPayload[:5])                   // truncated

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic. Errors are expected for malformed input.
		parseSessionBind(data)
	})
}
