package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"
)

// SignKind classifies the data a client asks the agent to sign.
type SignKind string

const (
	// SignKindUserauth is an SSH public-key user authentication request.
	SignKindUserauth SignKind = "userauth"
	// SignKindPam is a pam_ssh_agent_auth challenge (sudo and other PAM
	// services authenticating with the forwarded agent).
	SignKindPam SignKind = "pam"
	// SignKindOther is any other data from a local caller (no session-bind),
	// such as an SSHSIG for git commit signing.
	SignKindOther SignKind = "other"
)

func validSignKind(s string) bool {
	switch SignKind(s) {
	case SignKindUserauth, SignKindPam, SignKindOther:
		return true
	}
	return false
}

// SignRequest describes what a sign request is for, as far as the proxy can
// tell from the signed data. Pam is non-nil only for SignKindPam.
type SignRequest struct {
	Kind SignKind
	Pam  *PamRequest
}

// PamRequest holds the fields of a pam_ssh_agent_auth challenge. Every field
// is written by the process that talks to the agent socket; on a forwarded
// chain that is the remote host, so they are claims, not facts. Only the
// session-bind destination is authenticated.
type PamRequest struct {
	User      string   // PAM_USER: account being authenticated
	RUser     string   // requesting user (PAM_RUSER / SUDO_USER / uid)
	Service   string   // PAM service name, e.g. "sudo"
	CWD       string   // working directory of the PAM application
	Argv      []string // command line of the PAM application; nil if unavailable
	Hostname  string   // gethostname() of the verifying host
	Timestamp time.Time
}

// pam_ssh_agent_auth 0.10.x constants (ssh2.h).
const (
	pamAgentAuthRequestV1     = 101 // PAM_SSH_AGENT_AUTH_REQUESTv1
	sshMsgUserauthTrustReq    = 54  // SSH2_MSG_USERAUTH_TRUST_REQUEST
	pamAgentAuthServiceString = "pam_ssh_agent_auth"
	pamMaxCookie              = 255
	pamMinCookie              = 16
	pamMaxArgs                = 255
	pamMaxArgLen              = 256 // proc_pid_cmdline can store one byte past MAX_LEN_PER_CMDLINE_ARG
	pamMaxName                = 256
	pamMaxCWD                 = 1024
)

var errNotPamChallenge = errors.New("not a pam_ssh_agent_auth challenge")

// parsePamAgentAuthSignData parses data as a pam_ssh_agent_auth 0.10.x
// challenge for key. The layout (userauth_pubkey_from_id.c and
// pamsshagentauth_session_id2_gen in iterate_ssh_agent_keys.c):
//
//	string  session_id2
//	byte    54 (SSH2_MSG_USERAUTH_TRUST_REQUEST)
//	string  ruser
//	string  "pam_ssh_agent_auth"
//	string  "publickey"
//	bool    1
//	string  key algorithm
//	string  public key blob
//
// session_id2:
//
//	uint32  101 (PAM_SSH_AGENT_AUTH_REQUESTv1)
//	string  cookie (16..255 random bytes)
//	string  user, ruser, servicename, cwd
//	string  action: empty, or uint32 argc followed by argc strings
//	string  hostname
//	uint64  timestamp
//
// Parsing is strict: any deviation returns an error, and errNotPamChallenge
// when the data does not carry the format's fixed markers at all.
func parsePamAgentAuthSignData(data []byte, key ssh.PublicKey) (*PamRequest, error) {
	sid, rest, err := readSSHString(data)
	if err != nil || len(sid) < 4 || binary.BigEndian.Uint32(sid[:4]) != pamAgentAuthRequestV1 {
		return nil, errNotPamChallenge
	}
	if len(rest) < 1 || rest[0] != sshMsgUserauthTrustReq {
		return nil, errNotPamChallenge
	}
	rest = rest[1:]
	outerRUser, rest, err := readSSHString(rest)
	if err != nil {
		return nil, errNotPamChallenge
	}
	service, rest, err := readSSHString(rest)
	if err != nil || string(service) != pamAgentAuthServiceString {
		return nil, errNotPamChallenge
	}

	// From here on the data claims to be a pam_ssh_agent_auth challenge;
	// report specific errors.
	method, rest, err := readSSHString(rest)
	if err != nil || string(method) != "publickey" {
		return nil, fmt.Errorf("pam challenge: method is not publickey")
	}
	if len(rest) < 1 || rest[0] != 1 {
		return nil, fmt.Errorf("pam challenge: missing signature flag")
	}
	rest = rest[1:]
	algorithm, rest, err := readSSHString(rest)
	if err != nil || !algorithmMatchesKey(string(algorithm), key.Type()) {
		return nil, fmt.Errorf("pam challenge: key algorithm does not match requested signing key")
	}
	keyBlob, rest, err := readSSHString(rest)
	if err != nil || !bytes.Equal(keyBlob, key.Marshal()) {
		return nil, fmt.Errorf("pam challenge: key does not match requested signing key")
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("pam challenge: trailing data")
	}

	req, err := parsePamSessionID2(sid[4:])
	if err != nil {
		return nil, fmt.Errorf("pam challenge: %w", err)
	}
	if req.RUser != string(outerRUser) {
		return nil, fmt.Errorf("pam challenge: requesting user differs between header and body")
	}
	return req, nil
}

func parsePamSessionID2(r []byte) (*PamRequest, error) {
	field := func(name string, max int) (string, error) {
		v, rest, err := readSSHString(r)
		if err != nil {
			return "", fmt.Errorf("%s: %w", name, err)
		}
		if len(v) > max {
			return "", fmt.Errorf("%s: length %d exceeds %d", name, len(v), max)
		}
		r = rest
		return string(v), nil
	}

	cookie, rest, err := readSSHString(r)
	if err != nil {
		return nil, fmt.Errorf("cookie: %w", err)
	}
	if len(cookie) < pamMinCookie || len(cookie) > pamMaxCookie {
		return nil, fmt.Errorf("cookie length %d is outside %d..%d", len(cookie), pamMinCookie, pamMaxCookie)
	}
	r = rest

	req := &PamRequest{}
	if req.User, err = field("user", pamMaxName); err != nil {
		return nil, err
	}
	if req.RUser, err = field("ruser", pamMaxName); err != nil {
		return nil, err
	}
	if req.Service, err = field("service", pamMaxName); err != nil {
		return nil, err
	}
	if req.CWD, err = field("cwd", pamMaxCWD); err != nil {
		return nil, err
	}

	action, rest, err := readSSHString(r)
	if err != nil {
		return nil, fmt.Errorf("action: %w", err)
	}
	r = rest
	if len(action) > 0 {
		if req.Argv, err = parsePamAction(action); err != nil {
			return nil, err
		}
	}

	if req.Hostname, err = field("hostname", pamMaxName); err != nil {
		return nil, err
	}
	if len(r) != 8 {
		return nil, fmt.Errorf("timestamp: expected 8 trailing bytes, have %d", len(r))
	}
	ts := binary.BigEndian.Uint64(r)
	if ts > 1<<62 {
		return nil, fmt.Errorf("timestamp out of range")
	}
	req.Timestamp = time.Unix(int64(ts), 0)
	return req, nil
}

func parsePamAction(a []byte) ([]string, error) {
	if len(a) < 4 {
		return nil, fmt.Errorf("action: short argument count")
	}
	count := binary.BigEndian.Uint32(a[:4])
	if count > pamMaxArgs {
		return nil, fmt.Errorf("action: %d arguments exceeds %d", count, pamMaxArgs)
	}
	a = a[4:]
	argv := make([]string, 0, count)
	for i := uint32(0); i < count; i++ {
		arg, rest, err := readSSHString(a)
		if err != nil {
			return nil, fmt.Errorf("action argument %d: %w", i, err)
		}
		if len(arg) > pamMaxArgLen {
			return nil, fmt.Errorf("action argument %d: length %d exceeds %d", i, len(arg), pamMaxArgLen)
		}
		argv = append(argv, string(arg))
		a = rest
	}
	if len(a) != 0 {
		return nil, fmt.Errorf("action: trailing data")
	}
	return argv, nil
}

// Command returns the claimed command line, sanitized for display and
// matching: the program's base name (NixOS runs sudo from a store path)
// followed by its arguments, joined by spaces, control characters replaced.
// Logs keep the full argv.
func (r *PamRequest) Command() string {
	if r == nil || len(r.Argv) == 0 {
		return ""
	}
	parts := make([]string, len(r.Argv))
	for i, a := range r.Argv {
		if i == 0 {
			if j := strings.LastIndex(a, "/"); j >= 0 && j < len(a)-1 {
				a = a[j+1:]
			}
		}
		parts[i] = sanitizeDisplay(a, pamMaxArgLen)
	}
	return strings.Join(parts, " ")
}

// pamFreshness bounds how far a challenge timestamp may be from local time.
// Genuine challenges are minted immediately before the sign request.
const pamFreshness = 5 * time.Minute

// checkPamBinding checks a forwarded pam challenge against the authenticated
// destination: the claimed hostname must name the destination host, and the
// timestamp must be recent. A relayed challenge from a different host fails
// the hostname check.
func checkPamBinding(req *PamRequest, dest string, now time.Time) *signValidationError {
	if dest == "" {
		return &signValidationError{rule: "pam-dest-unknown",
			err: fmt.Errorf("pam challenge on a forwarded chain whose destination name is unknown (claims host %q)", sanitizeDisplay(req.Hostname, 64))}
	}
	if !sameHost(req.Hostname, dest) {
		return &signValidationError{rule: "pam-host-mismatch",
			err: fmt.Errorf("pam challenge claims host %q but the session is bound to %q", sanitizeDisplay(req.Hostname, 64), dest)}
	}
	skew := now.Sub(req.Timestamp)
	if skew < 0 {
		skew = -skew
	}
	if skew > pamFreshness {
		return &signValidationError{rule: "pam-stale",
			err: fmt.Errorf("pam challenge timestamp %s is %s from local time", req.Timestamp.UTC().Format(time.RFC3339), skew.Round(time.Second))}
	}
	return nil
}

// sameHost compares the first DNS label of a claimed hostname with the first
// label of a destination (which may carry a user@ prefix), case-insensitively.
func sameHost(claimed, dest string) bool {
	if i := strings.LastIndex(dest, "@"); i >= 0 {
		dest = dest[i+1:]
	}
	first := func(s string) string {
		if i := strings.Index(s, "."); i >= 0 {
			return s[:i]
		}
		return s
	}
	c, d := first(claimed), first(dest)
	return c != "" && strings.EqualFold(c, d)
}

// signValidationError is a deny produced before policy evaluation, carrying
// the rule name to log.
type signValidationError struct {
	rule string
	err  error
}

func (e *signValidationError) Error() string { return e.err.Error() }

// sanitizeDisplay replaces control and non-printable characters with '?'
// and truncates to max runes, so remote-supplied strings are safe in the
// journal, status bar and PIN popup.
func sanitizeDisplay(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= max {
			b.WriteString("…")
			break
		}
		if r == unicode.ReplacementChar || !unicode.IsPrint(r) {
			b.WriteByte('?')
		} else {
			b.WriteRune(r)
		}
		n++
	}
	return b.String()
}

// Label returns a short display label for the request, e.g.
// "sudo@or3: sudo true". Empty for non-pam requests.
func (s *SignRequest) Label() string {
	if s == nil || s.Kind != SignKindPam || s.Pam == nil {
		return ""
	}
	svc := sanitizeDisplay(s.Pam.Service, 32)
	host := sanitizeDisplay(s.Pam.Hostname, 64)
	cmd := s.Pam.Command()
	if cmd == "" {
		return fmt.Sprintf("%s@%s", svc, host)
	}
	return fmt.Sprintf("%s@%s: %s", svc, host, cmd)
}
