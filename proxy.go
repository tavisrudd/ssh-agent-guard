package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// pendingConfirms tracks the number of in-flight confirmation requests
// across all connections. Used with ConfirmConfig.MaxPending to prevent
// same-user processes from flooding the confirmation UI.
var pendingConfirms atomic.Int32

const maxSessionBindings = 16

// ProxyAgent wraps an upstream ExtendedAgent, intercepting operations
// for logging and policy enforcement. One instance per client connection.
type ProxyAgent struct {
	upstream       agent.ExtendedAgent
	caller         *CallerContext
	logger         *Logger
	knownHosts     *KnownHostsResolver
	policy         *Policy
	confirmCfg     *ConfirmConfig
	session        *SessionBindInfo // aggregate context for the authenticated binding chain
	bindings       []*SessionBindInfo
	sessionInvalid bool
	ctx            context.Context // cancelled when client connection closes
	signCount      int             // number of sign requests on this connection
}

var errNotPermitted = errors.New("operation not permitted through proxy")

func (p *ProxyAgent) List() ([]*agent.Key, error) {
	keys, err := p.upstream.List()
	if err != nil {
		return nil, err
	}
	if verbose {
		log.Printf("list: %d keys for %s (pid %d)", len(keys), p.caller.Name, p.caller.PID)
	}
	return keys, nil
}

// Sign is called by ServeAgent for non-ExtendedAgent dispatch.
// Since we implement ExtendedAgent, ServeAgent calls SignWithFlags instead,
// but we implement Sign for interface completeness.
func (p *ProxyAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	p.signCount++
	result := p.evalAndConfirm(key, data)
	if result.Action == Deny {
		return nil, errNotPermitted
	}
	return p.upstream.Sign(key, data)
}

// SignWithFlags is the primary signing path — ServeAgent calls this for
// any ExtendedAgent when processing SSH_AGENTC_SIGN_REQUEST.
func (p *ProxyAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	p.signCount++
	result := p.evalAndConfirm(key, data)
	if result.Action == Deny {
		return nil, errNotPermitted
	}
	return p.upstream.SignWithFlags(key, data, flags)
}

// evalAndConfirm evaluates policy and runs confirmation if needed.
// The confirmation method is chosen based on context:
//   - Active display → YubiKey touch ("touch")
//   - No display + YubiKey → PIN via tmux popup ("pin")
//   - No display + no YubiKey → deny ("missing")
func (p *ProxyAgent) evalAndConfirm(key ssh.PublicKey, data []byte) EvalResult {
	keyFP := ssh.FingerprintSHA256(key)
	if err := p.validateSessionForSign(data, key); err != nil {
		result := EvalResult{Action: Deny, RuleName: "session-bind-validation"}
		log.Printf("sign: invalid session binding for %s pid=%d: %v", p.caller.Name, p.caller.PID, err)
		p.logger.UpdateSignStatus(p.caller, key, p.session, result)
		forensics := collectDenyForensics(p.caller, p.session, keyFP, p.policy, p.signCount)
		p.logger.LogSign(p.caller, key, p.session, result, forensics)
		return result
	}
	result := p.policy.Evaluate(p.caller, p.session, keyFP)

	// Update status bar immediately
	p.logger.UpdateSignStatus(p.caller, key, p.session, result)

	if result.Action != Confirm {
		var forensics *DenyForensics
		if result.Action == Deny {
			forensics = collectDenyForensics(p.caller, p.session, keyFP, p.policy, p.signCount)
		}
		p.logger.LogSign(p.caller, key, p.session, result, forensics)
		return result
	}

	// Rate-limit concurrent confirmations to prevent prompt flooding.
	if max := p.confirmCfg.MaxPending; max > 0 {
		if n := pendingConfirms.Add(1); n > int32(max) {
			pendingConfirms.Add(-1)
			dest := SignDest(p.caller, p.session)
			log.Printf("confirm: rate-limited (%d/%d pending), denying %s → %s",
				n-1, max, p.caller.Name, dest)
			result.Action = Deny
			result.ConfirmMethod = "rate-limited"
			forensics := collectDenyForensics(p.caller, p.session, keyFP, p.policy, p.signCount)
			p.logger.LogSign(p.caller, key, p.session, result, forensics)
			return result
		}
		defer pendingConfirms.Add(-1)
	}

	dest := SignDest(p.caller, p.session)
	var ok bool

	// Determine confirmation method based on physical presence:
	// Active display → user is at the keyboard → YubiKey touch
	// No display + YubiKey → PIN via tmux popup
	// No display + no YubiKey → deny
	if hasActiveDisplay() {
		result.ConfirmMethod = "touch"
	} else if p.confirmCfg.HasYubiKey() {
		result.ConfirmMethod = "pin"
	} else {
		result.ConfirmMethod = "missing"
	}

	// Show confirming state on status bar (unless immediate deny)
	if result.ConfirmMethod != "missing" {
		p.logger.SetConfirming(p.caller, key, p.session, result)
	}

	switch result.ConfirmMethod {
	case "touch":
		log.Printf("confirm: method=touch for %s → %s", p.caller.Name, dest)
		ok = p.confirmCfg.ConfirmHMAC(p.ctx)
	case "pin":
		log.Printf("confirm: method=pin for %s → %s", p.caller.Name, dest)
		ok = p.confirmCfg.ConfirmPIN(p.ctx, p.caller, p.session, key)
	default:
		log.Printf("confirm: method=missing (no display, no YubiKey) for %s → %s", p.caller.Name, dest)
		ok = false
	}

	result.Confirmed = &ok
	if ok {
		result.Action = Allow
	} else {
		result.Action = Deny
	}

	var forensics *DenyForensics
	if result.Action == Deny {
		forensics = collectDenyForensics(p.caller, p.session, keyFP, p.policy, p.signCount)
	}
	p.logger.LogSign(p.caller, key, p.session, result, forensics)
	return result
}

// Key management operations are blocked through the proxy.
// Keys are managed directly on gpg-agent (via smartcard/scdaemon).

func (p *ProxyAgent) Add(key agent.AddedKey) error {
	p.logger.LogMutation(p.caller, "add", collectMutationForensics(p.caller))
	return errNotPermitted
}

func (p *ProxyAgent) Remove(key ssh.PublicKey) error {
	p.logger.LogMutation(p.caller, "remove", collectMutationForensics(p.caller))
	return errNotPermitted
}

func (p *ProxyAgent) RemoveAll() error {
	p.logger.LogMutation(p.caller, "remove-all", collectMutationForensics(p.caller))
	return errNotPermitted
}

func (p *ProxyAgent) Lock(passphrase []byte) error {
	p.logger.LogMutation(p.caller, "lock", collectMutationForensics(p.caller))
	return errNotPermitted
}

func (p *ProxyAgent) Unlock(passphrase []byte) error {
	p.logger.LogMutation(p.caller, "unlock", collectMutationForensics(p.caller))
	return errNotPermitted
}

// Signers returns signers for all available keys. Not called by ServeAgent
// (only used when the agent is consumed as a local signer). Delegate as-is.
func (p *ProxyAgent) Signers() ([]ssh.Signer, error) {
	return p.upstream.Signers()
}

// Extension handles SSH agent protocol extensions (e.g. session-bind).
// Intercepts session-bind@openssh.com to extract destination host context
// for forwarded agent requests.
func (p *ProxyAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType == "session-bind@openssh.com" {
		if len(p.bindings) >= maxSessionBindings {
			err := fmt.Errorf("too many session bindings (maximum %d)", maxSessionBindings)
			p.poisonSession("sequence", err)
			return nil, errNotPermitted
		}
		info, err := parseSessionBind(contents)
		if err != nil {
			p.poisonSession("parse/verify", err)
			return nil, errNotPermitted
		}
		duplicate, err := p.validateNextBinding(info)
		if err != nil {
			p.poisonSession("sequence", err)
			return nil, errNotPermitted
		}

		// Preserve destination constraints in an upstream OpenSSH agent when it
		// supports session-bind. Agents such as gpg-agent commonly do not.
		response, upstreamErr := p.upstream.Extension(extensionType, contents)
		if upstreamErr != nil && !errors.Is(upstreamErr, agent.ErrExtensionUnsupported) {
			p.poisonSession("upstream rejection", upstreamErr)
			return nil, upstreamErr
		}

		if duplicate {
			if upstreamErr != nil {
				return []byte{6}, nil
			}
			return response, nil
		}
		if p.knownHosts != nil {
			info.DestHostname = p.knownHosts.Resolve(info.DestKeyFingerprint)
		}
		p.bindings = append(p.bindings, info)
		info.IsForwarded = info.BindingForwarded
		for _, binding := range p.bindings[:len(p.bindings)-1] {
			info.IsForwarded = info.IsForwarded || binding.BindingForwarded
		}
		p.session = info
		if verbose {
			log.Printf("session-bind: dest=%s fp=%s forwarded-chain=%v caller=%s pid=%d",
				info.DestHostname, info.DestKeyFingerprint[:19], info.IsForwarded,
				p.caller.Name, p.caller.PID)
		}

		// When the session is forwarded, the local SSH process's cmdline
		// destination is the intermediate host (the first hop), not the
		// final destination. Move it to ForwardedVia so that:
		//   - ssh_dest falls through to session-bind's DestHostname (actual destination)
		//   - forwarded_via reflects the intermediate hop
		// Two cases:
		//   - Non-mux: SSHDest has the intermediate host from cmdline → move it
		//   - Mux: master renamed its cmdline, SSHDest is empty → extract
		//     from the socket path using the user's ControlPath format
		if p.session.IsForwarded {
			if p.caller.SSHDest != "" {
				p.caller.ForwardedVia = p.caller.SSHDest
				p.caller.SSHDest = ""
			} else if via := extractMuxVia(p.caller.Cmdline); via != "" {
				p.caller.ForwardedVia = via
			}
		}
		if upstreamErr != nil {
			// SSH_AGENT_SUCCESS. x/crypto intentionally keeps this protocol
			// constant private, but Extension responses are raw agent messages.
			return []byte{6}, nil
		}
		return response, nil
	} else if verbose {
		log.Printf("extension: type=%s caller=%s pid=%d", extensionType, p.caller.Name, p.caller.PID)
	}
	return p.upstream.Extension(extensionType, contents)
}

func (p *ProxyAgent) poisonSession(stage string, err error) {
	p.sessionInvalid = true
	p.session = &SessionBindInfo{IsForwarded: true, BindingForwarded: true}
	if p.caller.SSHDest != "" {
		p.caller.ForwardedVia = p.caller.SSHDest
		p.caller.SSHDest = ""
	}
	log.Printf("session-bind %s: %v (connection poisoned)", stage, err)
}

func (p *ProxyAgent) validateNextBinding(info *SessionBindInfo) (bool, error) {
	if p.sessionInvalid {
		return false, errors.New("an earlier session-bind failed")
	}
	for _, binding := range p.bindings {
		if bytes.Equal(binding.SessionID, info.SessionID) {
			if bytes.Equal(binding.HostKeyBlob, info.HostKeyBlob) {
				return true, nil
			}
			return false, errors.New("session identifier is bound to a different host key")
		}
	}
	if len(p.bindings) > 0 && !p.bindings[len(p.bindings)-1].BindingForwarded {
		return false, errors.New("cannot extend a connection already bound for authentication")
	}
	return false, nil
}

func (p *ProxyAgent) validateSessionForSign(data []byte, key ssh.PublicKey) error {
	if p.sessionInvalid {
		return errors.New("session-bind validation previously failed")
	}
	if len(p.bindings) == 0 {
		return nil
	}
	last := p.bindings[len(p.bindings)-1]
	if last.BindingForwarded {
		return errors.New("last binding is for forwarding, not authentication")
	}
	return validateUserauthSignData(data, last, key, p.session.IsForwarded)
}
