package main

import (
	"context"
	"errors"
	"log"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// ProxyAgent wraps an upstream ExtendedAgent, intercepting operations
// for logging and policy enforcement. One instance per client connection.
type ProxyAgent struct {
	upstream   agent.ExtendedAgent
	caller     *CallerContext
	logger     *Logger
	knownHosts *KnownHostsResolver
	policy     *Policy
	confirmCfg *ConfirmConfig
	session    *SessionBindInfo // most recent session-bind on this connection
	ctx        context.Context  // cancelled when client connection closes
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
	result := p.evalAndConfirm(key)
	if result.Action == Deny {
		return nil, errNotPermitted
	}
	return p.upstream.Sign(key, data)
}

// SignWithFlags is the primary signing path — ServeAgent calls this for
// any ExtendedAgent when processing SSH_AGENTC_SIGN_REQUEST.
func (p *ProxyAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	result := p.evalAndConfirm(key)
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
func (p *ProxyAgent) evalAndConfirm(key ssh.PublicKey) EvalResult {
	result := p.policy.Evaluate(p.caller, p.session, ssh.FingerprintSHA256(key))

	// Update status bar immediately
	p.logger.UpdateSignStatus(p.caller, key, p.session, result)

	if result.Action != Confirm {
		p.logger.LogSign(p.caller, key, p.session, result)
		return result
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
	p.logger.LogSign(p.caller, key, p.session, result)
	return result
}


// Key management operations are blocked through the proxy.
// Keys are managed directly on gpg-agent (via smartcard/scdaemon).

func (p *ProxyAgent) Add(key agent.AddedKey) error {
	p.logger.LogMutation(p.caller, "add")
	return errNotPermitted
}

func (p *ProxyAgent) Remove(key ssh.PublicKey) error {
	p.logger.LogMutation(p.caller, "remove")
	return errNotPermitted
}

func (p *ProxyAgent) RemoveAll() error {
	p.logger.LogMutation(p.caller, "remove-all")
	return errNotPermitted
}

func (p *ProxyAgent) Lock(passphrase []byte) error {
	p.logger.LogMutation(p.caller, "lock")
	return errNotPermitted
}

func (p *ProxyAgent) Unlock(passphrase []byte) error {
	p.logger.LogMutation(p.caller, "unlock")
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
		info, err := parseSessionBind(contents)
		if err != nil {
			log.Printf("session-bind parse: %v", err)
		} else {
			// Resolve hostname from known_hosts
			if p.knownHosts != nil {
				info.DestHostname = p.knownHosts.Resolve(info.DestKeyFingerprint)
			}
			p.session = info
			if verbose {
				log.Printf("session-bind: dest=%s fp=%s forwarded=%v caller=%s pid=%d",
					info.DestHostname, info.DestKeyFingerprint[:19], info.IsForwarded,
					p.caller.Name, p.caller.PID)
			}
		}
	} else if verbose {
		log.Printf("extension: type=%s caller=%s pid=%d", extensionType, p.caller.Name, p.caller.PID)
	}
	return p.upstream.Extension(extensionType, contents)
}
