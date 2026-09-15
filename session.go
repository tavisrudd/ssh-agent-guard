package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SessionBindInfo holds context extracted from an SSH session-bind@openssh.com
// extension message. OpenSSH 8.9+ sends this before sign requests, containing
// the server's host key and whether the agent is forwarded.
type SessionBindInfo struct {
	DestKeyFingerprint string // SHA256 fingerprint of the destination host key
	DestHostname       string // resolved via known_hosts reverse lookup
	IsForwarded        bool   // true when any earlier hop forwarded the agent
	SessionID          []byte // authenticated SSH session identifier (not logged)
	BindingForwarded   bool   // forwarding flag for this individual binding
	HostKeyBlob        []byte // authenticated destination key (not logged)
}

const (
	maxSessionIDBytes   = 128
	maxSessionBindBytes = 256 * 1024
)

// parseSessionBind decodes a session-bind@openssh.com extension payload.
// Wire format per PROTOCOL.agent: string hostkey, string session_id, string signature, bool is_forwarding
func parseSessionBind(data []byte) (*SessionBindInfo, error) {
	// Match OpenSSH's maximum agent packet size. In particular, reject large
	// certificates before parsing or retaining their attacker-controlled fields.
	if len(data) > maxSessionBindBytes {
		return nil, fmt.Errorf("session-bind payload length %d exceeds %d", len(data), maxSessionBindBytes)
	}
	r := data

	// hostkey blob (SSH wire-format public key)
	hostKeyBlob, r, err := readSSHString(r)
	if err != nil {
		return nil, fmt.Errorf("hostkey: %w", err)
	}

	// session_id — authenticated by the host key signature below
	sessionID, r, err := readSSHString(r)
	if err != nil {
		return nil, fmt.Errorf("session_id: %w", err)
	}
	if len(sessionID) == 0 || len(sessionID) > maxSessionIDBytes {
		return nil, fmt.Errorf("session_id length %d is outside 1..%d", len(sessionID), maxSessionIDBytes)
	}

	// signature over session_id by hostkey
	signatureBlob, r, err := readSSHString(r)
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}

	// is_forwarding flag
	if len(r) != 1 {
		return nil, fmt.Errorf("short read for forwarding flag")
	}
	if r[0] > 1 {
		return nil, fmt.Errorf("invalid forwarding flag %d", r[0])
	}
	isForwarded := r[0] == 1

	key, err := ssh.ParsePublicKey(hostKeyBlob)
	if err != nil {
		return nil, fmt.Errorf("parse host key: %w", err)
	}
	var signature ssh.Signature
	if err := ssh.Unmarshal(signatureBlob, &signature); err != nil {
		return nil, fmt.Errorf("parse signature: %w", err)
	}
	if err := validateSignatureTrailer(&signature); err != nil {
		return nil, err
	}
	if err := key.Verify(sessionID, &signature); err != nil {
		return nil, fmt.Errorf("verify signature: %w", err)
	}

	return &SessionBindInfo{
		DestKeyFingerprint: ssh.FingerprintSHA256(key),
		SessionID:          append([]byte(nil), sessionID...),
		BindingForwarded:   isForwarded,
		IsForwarded:        isForwarded,
		HostKeyBlob:        append([]byte(nil), hostKeyBlob...),
	}, nil
}

func validateSignatureTrailer(signature *ssh.Signature) error {
	switch signature.Format {
	case ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256:
		// Security-key signatures append one byte of flags and a uint32 counter.
		if len(signature.Rest) != 5 {
			return fmt.Errorf("invalid security-key signature trailer length %d", len(signature.Rest))
		}
	default:
		if len(signature.Rest) != 0 {
			return fmt.Errorf("trailing signature data")
		}
	}
	return nil
}

// validateUserauthSignData ensures a sign request is an SSH public-key userauth
// request for the bound session and requested key. Forwarded chains must use
// OpenSSH's hostbound method so the final destination key is part of the data.
func validateUserauthSignData(data []byte, binding *SessionBindInfo, key ssh.PublicKey, requireHostbound bool) error {
	sessionID, rest, err := readSSHString(data)
	if err != nil || !bytes.Equal(sessionID, binding.SessionID) {
		return fmt.Errorf("sign request is not bound to the final SSH session")
	}
	if len(rest) < 1 || rest[0] != 50 { // SSH2_MSG_USERAUTH_REQUEST
		return fmt.Errorf("sign request is not SSH user authentication")
	}
	rest = rest[1:]
	_, rest, err = readSSHString(rest) // username
	if err != nil {
		return fmt.Errorf("userauth username: %w", err)
	}
	service, rest, err := readSSHString(rest)
	if err != nil || string(service) != "ssh-connection" {
		return fmt.Errorf("invalid userauth service")
	}
	method, rest, err := readSSHString(rest)
	if err != nil {
		return fmt.Errorf("userauth method: %w", err)
	}
	if len(rest) < 1 || rest[0] != 1 {
		return fmt.Errorf("userauth request does not contain a signature")
	}
	rest = rest[1:]
	algorithm, rest, err := readSSHString(rest)
	if err != nil {
		return fmt.Errorf("userauth key algorithm: %w", err)
	}
	if !algorithmMatchesKey(string(algorithm), key.Type()) {
		return fmt.Errorf("userauth key algorithm does not match requested signing key")
	}
	keyBlob, rest, err := readSSHString(rest)
	if err != nil || !bytes.Equal(keyBlob, key.Marshal()) {
		return fmt.Errorf("userauth key does not match requested signing key")
	}

	switch string(method) {
	case "publickey-hostbound-v00@openssh.com":
		hostKeyBlob, trailing, err := readSSHString(rest)
		if err != nil || len(trailing) != 0 {
			return fmt.Errorf("invalid hostbound destination key")
		}
		if !bytes.Equal(hostKeyBlob, binding.HostKeyBlob) {
			return fmt.Errorf("hostbound destination key does not match final binding")
		}
	case "publickey":
		if requireHostbound {
			return fmt.Errorf("forwarded authentication requires publickey-hostbound")
		}
		if len(rest) != 0 {
			return fmt.Errorf("trailing legacy userauth data")
		}
	default:
		return fmt.Errorf("unsupported userauth method %q", method)
	}
	return nil
}

func algorithmMatchesKey(algorithm, keyType string) bool {
	if algorithm == keyType {
		return true
	}
	switch keyType {
	case ssh.KeyAlgoRSA:
		return algorithm == ssh.KeyAlgoRSASHA256 || algorithm == ssh.KeyAlgoRSASHA512
	case ssh.CertAlgoRSAv01:
		return algorithm == ssh.CertAlgoRSASHA256v01 || algorithm == ssh.CertAlgoRSASHA512v01
	default:
		return false
	}
}

// readSSHString reads a uint32-length-prefixed string from data.
func readSSHString(data []byte) ([]byte, []byte, error) {
	if len(data) < 4 {
		return nil, nil, fmt.Errorf("short read for length")
	}
	length := binary.BigEndian.Uint32(data[:4])
	if uint32(len(data)-4) < length {
		return nil, nil, fmt.Errorf("short read: need %d, have %d", length, len(data)-4)
	}
	return data[4 : 4+length], data[4+length:], nil
}

// KnownHostsResolver maps host key fingerprints to hostnames by parsing
// known_hosts files. Enables reverse lookup: given a host key from a
// session-bind, find which host it belongs to.
//
// Limitation: hashed known_hosts entries (HashKnownHosts yes) are skipped
// because the hash is one-way — we can't reverse a hashed hostname from a
// key fingerprint. When all entries are hashed, ssh_dest (session-bind fallback)
// and is_in_known_hosts policy matching won't work for forwarded agent sessions.
// Workaround: maintain a plaintext known_hosts alongside the hashed one via
// UserKnownHostsFile in ssh_config.
type KnownHostsResolver struct {
	byFingerprint map[string][]string // SHA256 fingerprint → hostnames
}

func NewKnownHostsResolver(paths ...string) *KnownHostsResolver {
	r := &KnownHostsResolver{
		byFingerprint: make(map[string][]string),
	}
	for _, path := range paths {
		r.loadFile(path)
	}
	return r
}

func (r *KnownHostsResolver) loadFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("known_hosts: %s: %v", path, err)
		return
	}

	loaded := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Skip hashed entries (|1|salt|hash format from HashKnownHosts).
		// These are HMAC-SHA1 hashes of the hostname — irreversible by design.
		// See the KnownHostsResolver doc comment for implications.
		if strings.HasPrefix(line, "|") {
			continue
		}
		// Skip @cert-authority / @revoked markers
		if strings.HasPrefix(line, "@") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		hostnames := fields[0]
		keyB64 := fields[2]

		keyBytes, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil {
			log.Printf("known_hosts: %s: bad base64 for host %s: %v", path, hostnames, err)
			continue
		}
		key, err := ssh.ParsePublicKey(keyBytes)
		if err != nil {
			log.Printf("known_hosts: %s: bad public key for host %s: %v", path, hostnames, err)
			continue
		}
		fp := ssh.FingerprintSHA256(key)

		for _, h := range strings.Split(hostnames, ",") {
			h = strings.TrimSpace(h)
			// Handle [host]:port format
			if strings.HasPrefix(h, "[") {
				if idx := strings.Index(h, "]:"); idx >= 0 {
					h = h[1:idx]
				} else if strings.HasSuffix(h, "]") {
					h = h[1 : len(h)-1]
				}
			}
			if h != "" {
				r.byFingerprint[fp] = appendUnique(r.byFingerprint[fp], h)
				loaded++
			}
		}
	}
	log.Printf("known_hosts: loaded %d entries from %s", loaded, path)
}

// Resolve returns the shortest hostname associated with a key fingerprint,
// or "" if the key is unknown.
func (r *KnownHostsResolver) Resolve(fingerprint string) string {
	hosts := r.byFingerprint[fingerprint]
	if len(hosts) == 0 {
		return ""
	}
	shortest := hosts[0]
	for _, h := range hosts[1:] {
		if len(h) < len(shortest) {
			shortest = h
		}
	}
	return shortest
}

func appendUnique(slice []string, s string) []string {
	for _, existing := range slice {
		if existing == s {
			return slice
		}
	}
	return append(slice, s)
}
