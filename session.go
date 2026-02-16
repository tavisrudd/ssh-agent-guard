package main

import (
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
	IsForwarded        bool   // true when agent access is forwarded
}

// parseSessionBind decodes a session-bind@openssh.com extension payload.
// Wire format per PROTOCOL.agent: string hostkey, string session_id, string signature, bool is_forwarding
func parseSessionBind(data []byte) (*SessionBindInfo, error) {
	r := data

	// hostkey blob (SSH wire-format public key)
	hostKeyBlob, r, err := readSSHString(r)
	if err != nil {
		return nil, fmt.Errorf("hostkey: %w", err)
	}

	// session_id — skip
	_, r, err = readSSHString(r)
	if err != nil {
		return nil, fmt.Errorf("session_id: %w", err)
	}

	// signature — skip
	_, r, err = readSSHString(r)
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}

	// is_forwarding flag
	if len(r) < 1 {
		return nil, fmt.Errorf("short read for forwarding flag")
	}
	isForwarded := r[0] != 0

	key, err := ssh.ParsePublicKey(hostKeyBlob)
	if err != nil {
		return nil, fmt.Errorf("parse host key: %w", err)
	}

	return &SessionBindInfo{
		DestKeyFingerprint: ssh.FingerprintSHA256(key),
		IsForwarded:        isForwarded,
	}, nil
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
			continue
		}
		key, err := ssh.ParsePublicKey(keyBytes)
		if err != nil {
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
