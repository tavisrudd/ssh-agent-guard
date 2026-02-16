package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

// Action represents a policy decision.
type Action int

const (
	Allow   Action = iota
	Deny    Action = iota
	Confirm Action = iota
)

func parseAction(s string) (Action, error) {
	switch strings.ToLower(s) {
	case "allow":
		return Allow, nil
	case "deny":
		return Deny, nil
	case "confirm":
		return Confirm, nil
	default:
		return Deny, fmt.Errorf("unknown action: %q", s)
	}
}

func (a Action) String() string {
	switch a {
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	case Confirm:
		return "confirm"
	default:
		return "unknown"
	}
}

// PolicyConfig is the top-level policy file structure.
type PolicyConfig struct {
	DefaultAction string            `yaml:"default_action"` // allow, deny, confirm
	Path          []string          `yaml:"path,omitempty"`  // extra dirs to search for binaries
	Rules         []Rule            `yaml:"rules"`
	Confirm       ConfirmPolicyYAML `yaml:"confirm,omitempty"`
}

// ConfirmPolicyYAML configures the two YubiKey confirmation methods.
type ConfirmPolicyYAML struct {
	// Touch: local YubiKey HMAC-SHA1 touch confirmation.
	// The daemon sends a fixed challenge to the YubiKey slot and waits
	// for the user to physically touch the key. The response is compared
	// against a pre-computed expected value stored in the state directory.
	Touch TouchConfirmYAML `yaml:"touch,omitempty"`

	// PIN: remote confirmation via tmux popup.
	// The user types a PIN which is sent as the HMAC challenge to a
	// different YubiKey slot (no touch required). Used when no local
	// display is available (e.g. SSH session).
	PIN PINConfirmYAML `yaml:"pin,omitempty"`
}

// TouchConfirmYAML configures local YubiKey HMAC touch confirmation.
type TouchConfirmYAML struct {
	Challenge string `yaml:"challenge,omitempty"` // hex string sent as HMAC challenge (default: "deadbeef")
	Slot      string `yaml:"slot,omitempty"`      // YubiKey HMAC slot number (default: "2")
	Timeout   string `yaml:"timeout,omitempty"`   // max wait for touch (default: "20s")
}

// PINConfirmYAML configures remote PIN confirmation via tmux popup.
type PINConfirmYAML struct {
	Slot    string `yaml:"slot,omitempty"`    // YubiKey HMAC slot number (default: "1")
	Timeout string `yaml:"timeout,omitempty"` // max wait for PIN entry (default: "120s")
}

// Rule is a single policy rule: if all match fields match, apply the action.
type Rule struct {
	Name   string    `yaml:"name,omitempty"` // optional label for logging
	Match  MatchSpec `yaml:"match"`
	Action string    `yaml:"action"`
}

// MatchSpec defines the conditions for a rule to match.
// All specified fields must match (AND logic). Unset fields are wildcards.
type MatchSpec struct {
	ProcessName        StringOrList      `yaml:"process_name,omitempty"`
	ParentProcessName  StringOrList      `yaml:"parent_process_name,omitempty"`
	Ancestor           StringOrList      `yaml:"ancestor,omitempty"`
	Command            string            `yaml:"command,omitempty"`
	SSHDest            string            `yaml:"ssh_dest,omitempty"`
	IsInKnownHosts     *bool             `yaml:"is_in_known_hosts,omitempty"`
	ForwardedVia       string            `yaml:"forwarded_via,omitempty"`
	IsForwarded        *bool             `yaml:"is_forwarded,omitempty"`
	Key                string            `yaml:"key,omitempty"`
	CWD                string            `yaml:"cwd,omitempty"`
	TmuxWindow         string            `yaml:"tmux_window,omitempty"`
	IsInContainer      *bool             `yaml:"is_in_container,omitempty"`
	Env                map[string]string `yaml:"env,omitempty"`
}

// StringOrList handles YAML values that can be a single string or a list.
type StringOrList []string

func (s *StringOrList) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		*s = []string{value.Value}
		return nil
	}
	if value.Kind == yaml.SequenceNode {
		var list []string
		if err := value.Decode(&list); err != nil {
			return err
		}
		*s = list
		return nil
	}
	return fmt.Errorf("expected string or list, got %v", value.Kind)
}

// Policy holds the loaded policy and provides thread-safe evaluation.
// A Policy always represents a valid, successfully parsed config (or defaults).
// Transient load errors flow through LoadResult, not Policy state.
type Policy struct {
	mu            sync.RWMutex
	config        *PolicyConfig
	defaultAction Action
	rules         []compiledRule
	path          string
	activeVersion time.Time        // mtime of successfully loaded config
	configSHA256  string           // hex SHA256 of active config file contents
	configContent string           // raw content of active config file (for snapshot logs)
	onReload      func(LoadResult) // called after Load() from Watch/SIGHUP (not initial load)
}

// LoadResult carries the outcome of a Load() call. On success, the Policy
// is updated and BadContent/BadConfigSHA are empty. On failure, the Policy
// keeps its previous valid state and the bad file data is here for logging.
type LoadResult struct {
	OK           bool     // true if config parsed successfully (or file absent)
	Errors       []string // parse/read errors (empty on success)
	BadConfigSHA string   // SHA256 of file that failed to parse (empty on success/read-error)
	BadContent   string   // raw content of file that failed to parse
}

// ConfigStatus is the config version/health info included in current.yaml
// so that status renderers can surface reload failures.
type ConfigStatus struct {
	ActiveVersion    string `yaml:"active_version"`
	ConfigSHA256     string `yaml:"config_sha256,omitempty"`
	IsCurrentVersion bool   `yaml:"is_current_version"`
}

// ConfigStatus returns a snapshot of the config version and health state.
// Checks the file on disk to determine if our loaded version is current.
func (p *Policy) ConfigStatus() ConfigStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var version string
	if !p.activeVersion.IsZero() {
		version = p.activeVersion.Format("2006-01-02T15:04:05")
	}

	isCurrent := true
	if info, err := os.Stat(p.path); err == nil {
		if p.activeVersion.IsZero() {
			// File appeared on disk but we never loaded one
			isCurrent = false
		} else {
			isCurrent = info.ModTime().Equal(p.activeVersion)
		}
	} else if !os.IsNotExist(err) {
		// Stat error (permissions, etc.) — can't verify
		isCurrent = false
	}
	// File doesn't exist + no active version → expected "no config" state → current

	return ConfigStatus{
		ActiveVersion:    version,
		ConfigSHA256:     p.configSHA256,
		IsCurrentVersion: isCurrent,
	}
}

// ConfigSHA256 returns the hex SHA256 of the active config file contents.
func (p *Policy) ConfigSHA256() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.configSHA256
}

// ConfigContent returns the raw content of the active config file.
func (p *Policy) ConfigContent() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.configContent
}

type compiledRule struct {
	name   string
	match  compiledMatch
	action Action
}

type compiledMatch struct {
	processName        []string
	parentProcessName  []string
	ancestor           []string
	command            *matchPattern
	sshDest            *matchPattern
	isInKnownHosts     *bool
	forwardedVia       *matchPattern
	isForwarded        *bool
	key                string
	cwd                *matchPattern
	tmuxWindow         *matchPattern
	isInContainer      *bool
	env                map[string]string
}

// matchPattern is either a glob or regex pattern.
type matchPattern struct {
	raw   string
	regex *regexp.Regexp // non-nil if regex mode (~prefix)
}

func compilePattern(s string) *matchPattern {
	if s == "" {
		return nil
	}
	if strings.HasPrefix(s, "~") {
		re, err := regexp.Compile(s[1:])
		if err != nil {
			log.Printf("policy: bad regex %q: %v", s, err)
			return nil
		}
		return &matchPattern{raw: s, regex: re}
	}
	return &matchPattern{raw: s}
}

// matchString tests a value against a pattern (glob or regex).
func (p *matchPattern) matchString(value string) bool {
	if p == nil {
		return true // unset = wildcard
	}
	if p.regex != nil {
		return p.regex.MatchString(value)
	}
	return globMatch(p.raw, value)
}

// globMatch implements simple glob matching with * and ?.
func globMatch(pattern, value string) bool {
	return deepGlob(pattern, value)
}

func deepGlob(pattern, value string) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			// Skip consecutive *
			for len(pattern) > 0 && pattern[0] == '*' {
				pattern = pattern[1:]
			}
			if len(pattern) == 0 {
				return true // trailing * matches everything
			}
			// Try matching rest of pattern at each position
			for i := 0; i <= len(value); i++ {
				if deepGlob(pattern, value[i:]) {
					return true
				}
			}
			return false
		case '?':
			if len(value) == 0 {
				return false
			}
			pattern = pattern[1:]
			value = value[1:]
		default:
			if len(value) == 0 || pattern[0] != value[0] {
				return false
			}
			pattern = pattern[1:]
			value = value[1:]
		}
	}
	return len(value) == 0
}

func NewPolicy(path string) (*Policy, LoadResult) {
	p := &Policy{path: path}
	result := p.Load()
	return p, result
}

// OnReload sets a callback invoked after Load() from Watch/SIGHUP.
// Must be set before calling Watch().
func (p *Policy) OnReload(fn func(LoadResult)) {
	p.onReload = fn
}

// Watch uses inotify to watch the policy file for changes and reloads
// when modified. Only reloads if the new config parses successfully.
func (p *Policy) Watch() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("policy: watch setup failed: %v, falling back to SIGHUP", err)
		return
	}

	// Watch the directory (not the file) so we catch symlink replacements
	dir := filepath.Dir(p.path)
	if err := watcher.Add(dir); err != nil {
		log.Printf("policy: watch %s failed: %v, falling back to SIGHUP", dir, err)
		watcher.Close()
		return
	}

	base := filepath.Base(p.path)
	go func() {
		defer watcher.Close()
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if filepath.Base(event.Name) != base {
					continue
				}
				if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
					result := p.Load()
					if p.onReload != nil {
						p.onReload(result)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("policy: watch error: %v", err)
			}
		}
	}()
}

func (p *Policy) Load() LoadResult {
	p.mu.Lock()
	defer p.mu.Unlock()

	config := &PolicyConfig{DefaultAction: "allow"}

	data, err := os.ReadFile(p.path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("policy: no config at %s, defaulting to confirm-all", p.path)
		} else {
			log.Printf("policy: read %s: %v", p.path, err)
		}
		p.config = config
		p.defaultAction = Confirm
		p.rules = nil
		p.activeVersion = time.Time{}
		p.configSHA256 = ""
		p.configContent = ""
		resolveBins()
		if os.IsNotExist(err) {
			return LoadResult{OK: true}
		}
		return LoadResult{OK: false, Errors: []string{err.Error()}}
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		log.Printf("policy: parse %s: %v (keeping previous)", p.path, err)
		badHash := sha256.Sum256(data)
		return LoadResult{
			OK:           false,
			Errors:       []string{err.Error()},
			BadConfigSHA: fmt.Sprintf("%x", badHash),
			BadContent:   string(data),
		}
	}

	defaultAction, err := parseAction(config.DefaultAction)
	if err != nil {
		log.Printf("policy: %v, defaulting to allow", err)
		defaultAction = Allow
	}

	var rules []compiledRule
	for i, r := range config.Rules {
		action, err := parseAction(r.Action)
		if err != nil {
			log.Printf("policy: rule %d: %v, skipping", i, err)
			continue
		}
		name := r.Name
		if name == "" {
			name = fmt.Sprintf("rule-%d", i)
		}
		rules = append(rules, compiledRule{
			name:   name,
			action: action,
			match:  compileMatch(r.Match),
		})
	}

	p.config = config
	p.defaultAction = defaultAction
	p.rules = rules
	hash := sha256.Sum256(data)
	p.configSHA256 = fmt.Sprintf("%x", hash)
	p.configContent = string(data)
	if info, err := os.Stat(p.path); err == nil {
		p.activeVersion = info.ModTime()
	}

	// Expand ~ in path entries and store atomically for findBin
	home := os.Getenv("HOME")
	var paths []string
	for _, dir := range config.Path {
		if strings.HasPrefix(dir, "~/") {
			dir = filepath.Join(home, dir[2:])
		}
		paths = append(paths, dir)
	}
	extraBinPathsVal.Store(paths)
	resolveBins()

	if verbose {
		log.Printf("policy: loaded %d rules from %s (default: %s)", len(rules), p.path, defaultAction)
	}

	return LoadResult{OK: true}
}

// ConfirmConfig returns a ConfirmConfig built from the current policy's
// confirm section, with defaults for any unset fields.
func (p *Policy) ConfirmConfig() ConfirmConfig {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return buildConfirmConfig(p.config)
}

func buildConfirmConfig(config *PolicyConfig) ConfirmConfig {
	cfg := DefaultConfirmConfig()
	if config == nil {
		return cfg
	}
	c := config.Confirm

	// Touch (local HMAC) overrides
	if c.Touch.Challenge != "" {
		cfg.Challenge = c.Touch.Challenge
	}
	if c.Touch.Slot != "" {
		cfg.Slot = c.Touch.Slot
	}
	if c.Touch.Timeout != "" {
		if d, err := time.ParseDuration(c.Touch.Timeout); err == nil {
			cfg.Timeout = d
		} else {
			log.Printf("policy: invalid confirm.touch.timeout %q: %v", c.Touch.Timeout, err)
		}
	}

	// PIN (remote) overrides
	if c.PIN.Slot != "" {
		cfg.PINSlot = c.PIN.Slot
	}
	if c.PIN.Timeout != "" {
		if d, err := time.ParseDuration(c.PIN.Timeout); err == nil {
			cfg.PINTimeout = d
		} else {
			log.Printf("policy: invalid confirm.pin.timeout %q: %v", c.PIN.Timeout, err)
		}
	}

	return cfg
}

func compileMatch(m MatchSpec) compiledMatch {
	return compiledMatch{
		processName:        m.ProcessName,
		parentProcessName:  m.ParentProcessName,
		ancestor:           m.Ancestor,
		command:            compilePattern(m.Command),
		sshDest:            compilePattern(m.SSHDest),
		isInKnownHosts:     m.IsInKnownHosts,
		forwardedVia:       compilePattern(m.ForwardedVia),
		isForwarded:        m.IsForwarded,
		key:                m.Key,
		cwd:                compilePattern(m.CWD),
		tmuxWindow:         compilePattern(m.TmuxWindow),
		isInContainer:      m.IsInContainer,
		env:                m.Env,
	}
}

// EvalResult holds the policy decision and the rule that produced it.
type EvalResult struct {
	Action        Action
	RuleName      string // "default" if no rule matched
	Confirmed     *bool  // nil unless action was confirm; true=touched, false=denied
	ConfirmMethod string // "touch", "pin", "missing" — set when Action==Confirm
}

// Evaluate checks a sign request against all rules. First match wins.
func (p *Policy) Evaluate(ctx *CallerContext, session *SessionBindInfo, keyFingerprint string) EvalResult {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, r := range p.rules {
		if r.match.matches(ctx, session, keyFingerprint) {
			return EvalResult{Action: r.action, RuleName: r.name}
		}
	}
	return EvalResult{Action: p.defaultAction, RuleName: "default"}
}

func (m *compiledMatch) matches(ctx *CallerContext, session *SessionBindInfo, keyFingerprint string) bool {
	// process_name: string or list — match CallerContext.Name
	if len(m.processName) > 0 {
		if !stringInList(ctx.Name, m.processName) {
			return false
		}
	}

	// parent_process_name: string or list — match immediate parent's Name
	if len(m.parentProcessName) > 0 {
		parentName := ""
		if len(ctx.Ancestry) > 1 {
			parentName = ctx.Ancestry[1].Name
		}
		if !stringInList(parentName, m.parentProcessName) {
			return false
		}
	}

	// ancestor: string or list — match any AncestorInfo.Name
	if len(m.ancestor) > 0 {
		found := false
		for _, a := range ctx.Ancestry {
			if stringInList(a.Name, m.ancestor) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// command: glob/regex against CallerContext.Cmdline
	if !m.command.matchString(ctx.Cmdline) {
		return false
	}

	// ssh_dest: the final SSH destination (from cmdline, falling back to session-bind)
	sshDest := ctx.SSHDest
	if sshDest == "" && session != nil {
		sshDest = session.DestHostname
	}
	if !m.sshDest.matchString(sshDest) {
		return false
	}

	// is_in_known_hosts: session-bind destination resolved against known_hosts
	if m.isInKnownHosts != nil && *m.isInKnownHosts {
		sessionDest := ""
		if session != nil {
			sessionDest = session.DestHostname
		}
		if sessionDest == "" {
			return false
		}
	}

	// forwarded_via: glob/regex against CallerContext.ForwardedVia
	if !m.forwardedVia.matchString(ctx.ForwardedVia) {
		return false
	}

	// is_forwarded: bool against SessionBindInfo.IsForwarded
	if m.isForwarded != nil {
		isForwarded := session != nil && session.IsForwarded
		if *m.isForwarded != isForwarded {
			return false
		}
	}

	// key: prefix match against key fingerprint
	if m.key != "" {
		if !strings.HasPrefix(keyFingerprint, m.key) {
			return false
		}
	}

	// cwd: glob/regex against CallerContext.CWD
	if !m.cwd.matchString(ctx.CWD) {
		return false
	}

	// tmux_window: glob/regex against CallerContext.TmuxWindow
	if !m.tmuxWindow.matchString(ctx.TmuxWindow) {
		return false
	}

	// is_in_container: bool against CallerContext.IsContainer
	if m.isInContainer != nil {
		if *m.isInContainer != ctx.IsContainer {
			return false
		}
	}

	// env: all specified env vars must match
	for k, v := range m.env {
		actual, ok := ctx.Env[k]
		if !ok || actual != v {
			return false
		}
	}

	return true
}

// RuleCheckResult holds the result of evaluating a single rule in verbose mode.
type RuleCheckResult struct {
	Name       string
	Action     string
	Matched    bool
	Mismatches []string // field names that didn't match
}

// EvaluateVerbose evaluates all rules and returns detailed match info for each.
// Used by --check mode for debugging policy configuration.
func (p *Policy) EvaluateVerbose(ctx *CallerContext, session *SessionBindInfo, keyFingerprint string) []RuleCheckResult {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var results []RuleCheckResult
	for _, r := range p.rules {
		mismatches := r.match.checkMismatches(ctx, session, keyFingerprint)
		results = append(results, RuleCheckResult{
			Name:       r.name,
			Action:     r.action.String(),
			Matched:    len(mismatches) == 0,
			Mismatches: mismatches,
		})
	}
	return results
}

// checkMismatches returns which fields don't match. Empty slice = full match.
func (m *compiledMatch) checkMismatches(ctx *CallerContext, session *SessionBindInfo, keyFingerprint string) []string {
	var mm []string

	if len(m.processName) > 0 && !stringInList(ctx.Name, m.processName) {
		mm = append(mm, fmt.Sprintf("process_name: want %v, got %q", m.processName, ctx.Name))
	}
	if len(m.parentProcessName) > 0 {
		parentName := ""
		if len(ctx.Ancestry) > 1 {
			parentName = ctx.Ancestry[1].Name
		}
		if !stringInList(parentName, m.parentProcessName) {
			mm = append(mm, fmt.Sprintf("parent_process_name: want %v, got %q", m.parentProcessName, parentName))
		}
	}
	if len(m.ancestor) > 0 {
		found := false
		for _, a := range ctx.Ancestry {
			if stringInList(a.Name, m.ancestor) {
				found = true
				break
			}
		}
		if !found {
			mm = append(mm, fmt.Sprintf("ancestor: want %v, not in ancestry", m.ancestor))
		}
	}
	if !m.command.matchString(ctx.Cmdline) {
		mm = append(mm, fmt.Sprintf("command: want %q, got %q", m.command.raw, ctx.Cmdline))
	}
	sshDest := ctx.SSHDest
	if sshDest == "" && session != nil {
		sshDest = session.DestHostname
	}
	if !m.sshDest.matchString(sshDest) {
		mm = append(mm, fmt.Sprintf("ssh_dest: want %q, got %q", m.sshDest.raw, sshDest))
	}
	if m.isInKnownHosts != nil && *m.isInKnownHosts {
		sessionDest := ""
		if session != nil {
			sessionDest = session.DestHostname
		}
		if sessionDest == "" {
			mm = append(mm, "is_in_known_hosts: no session-bind dest")
		}
	}
	if !m.forwardedVia.matchString(ctx.ForwardedVia) {
		mm = append(mm, fmt.Sprintf("forwarded_via: want %q, got %q", m.forwardedVia.raw, ctx.ForwardedVia))
	}
	if m.isForwarded != nil {
		isForwarded := session != nil && session.IsForwarded
		if *m.isForwarded != isForwarded {
			mm = append(mm, fmt.Sprintf("is_forwarded: want %v, got %v", *m.isForwarded, isForwarded))
		}
	}
	if m.key != "" && !strings.HasPrefix(keyFingerprint, m.key) {
		mm = append(mm, fmt.Sprintf("key: want prefix %q, got %q", m.key, keyFingerprint))
	}
	if !m.cwd.matchString(ctx.CWD) {
		mm = append(mm, fmt.Sprintf("cwd: want %q, got %q", m.cwd.raw, ctx.CWD))
	}
	if !m.tmuxWindow.matchString(ctx.TmuxWindow) {
		mm = append(mm, fmt.Sprintf("tmux_window: want %q, got %q", m.tmuxWindow.raw, ctx.TmuxWindow))
	}
	if m.isInContainer != nil && *m.isInContainer != ctx.IsContainer {
		mm = append(mm, fmt.Sprintf("is_in_container: want %v, got %v", *m.isInContainer, ctx.IsContainer))
	}
	for k, v := range m.env {
		actual := ctx.Env[k]
		if actual != v {
			mm = append(mm, fmt.Sprintf("env.%s: want %q, got %q", k, v, actual))
		}
	}
	return mm
}

func stringInList(s string, list []string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

func defaultPolicyPath() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "ssh-ag", "policy.yaml")
	}
	return filepath.Join(os.Getenv("HOME"), ".config", "ssh-ag", "policy.yaml")
}
