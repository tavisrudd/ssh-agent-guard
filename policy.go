package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

// builtinCodingAgents defines the default coding agent detection heuristics.
// These are always active and merge with any user-configured coding_agents.
var builtinCodingAgents = map[string]CodingAgentYAML{
	"claude":   {Env: map[string]string{"CLAUDECODE": "1"}},
	"cursor":   {Ancestors: []string{"cursor"}},
	"copilot":  {Ancestors: []string{"copilot"}},
	"aider":    {Ancestors: []string{"aider"}},
	"windsurf": {Ancestors: []string{"windsurf"}},
	"amp":      {Ancestors: []string{"amp"}},
	"pi":       {Ancestors: []string{"pi"}},
}

// codingAgentHeuristics holds the merged (builtin + config) per-agent detection rules.
type codingAgentHeuristics struct {
	agents map[string]CodingAgentYAML // agent name → heuristic set
}

// codingAgentHeuristicsVal is set by Policy.Load() and read by getCallerContextFromPID.
var codingAgentHeuristicsVal atomic.Value // stores *codingAgentHeuristics

// envVarsCaptureListVal holds the merged env var names to read from /proc.
// Set by Policy.Load(), read by readSelectedEnv.
var envVarsCaptureListVal atomic.Value // stores []string

// Action represents a policy decision.
type Action int

const (
	Allow Action = iota
	Deny
	Confirm
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
	DefaultAction    string                       `yaml:"default_action"`              // allow, deny, confirm
	Path             []string                     `yaml:"path,omitempty"`              // extra dirs to search for binaries
	CaptureExtraEnv  []string                     `yaml:"capture_extra_env_vars,omitempty"` // additional env vars to read from /proc
	CodingAgents     map[string]CodingAgentYAML   `yaml:"coding_agents,omitempty"`     // per-agent detection heuristics
	Rules            []Rule                       `yaml:"rules"`
	Confirm          ConfirmPolicyYAML            `yaml:"confirm,omitempty"`
}

// CodingAgentYAML defines detection heuristics for a single coding agent.
// A caller is identified as this agent if any env var matches OR any ancestor matches.
type CodingAgentYAML struct {
	Env       map[string]string `yaml:"env,omitempty"`       // env var name → expected value
	Ancestors []string          `yaml:"ancestors,omitempty"` // process names in ancestry
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

	// MaxPending limits the number of concurrent pending confirmations.
	// Excess requests are immediately denied. Prevents same-user processes
	// from flooding the confirmation UI. 0 means unlimited. Default: 3.
	MaxPending *int `yaml:"max_pending,omitempty"`
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
	IsCodingAgent      *bool             `yaml:"is_coding_agent,omitempty"`
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
	isCodingAgent      *bool
	env                map[string]string
}

// matchPattern is either a glob or regex pattern.
type matchPattern struct {
	raw   string
	regex *regexp.Regexp // non-nil if regex mode (~prefix)
}

// extractRuleLines parses YAML into a node tree and returns the line number
// of each entry in the "rules" sequence. Used for error reporting only.
func extractRuleLines(data []byte) []int {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(root.Content)-1; i += 2 {
		if root.Content[i].Value == "rules" {
			seq := root.Content[i+1]
			if seq.Kind != yaml.SequenceNode {
				return nil
			}
			lines := make([]int, len(seq.Content))
			for j, node := range seq.Content {
				lines[j] = node.Line
			}
			return lines
		}
	}
	return nil
}

// sanitizeYAMLError strips Go-internal type names from yaml.v3 error messages.
// "field foo not found in type main.MatchSpec" → "unknown field foo"
var yamlTypeRe = regexp.MustCompile(` not found in type \S+`)

func sanitizeYAMLError(msg string) string {
	return yamlTypeRe.ReplaceAllString(msg, " is not a valid field")
}

func compilePattern(s string) (*matchPattern, error) {
	if s == "" {
		return nil, nil
	}
	if strings.HasPrefix(s, "~") {
		re, err := regexp.Compile(s[1:])
		if err != nil {
			return nil, fmt.Errorf("bad regex %q: %v", s, err)
		}
		return &matchPattern{raw: s, regex: re}, nil
	}
	return &matchPattern{raw: s}, nil
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

// matchSSHDest matches an ssh_dest value against a pattern with hostname
// semantics: if the pattern doesn't contain '@', it matches against the
// hostname portion only (stripping any user@ prefix from the value).
// This means "github.com" matches both "github.com" (from session-bind)
// and "git@github.com" (from command line parsing).
// Patterns containing '@' match the full value as-is.
func matchSSHDest(p *matchPattern, value string) bool {
	if p == nil {
		return true // unset = wildcard
	}
	// If the pattern contains @, match against the full user@host value.
	if strings.Contains(p.raw, "@") {
		return p.matchString(value)
	}
	// Pattern has no @ — match against hostname only.
	host := value
	if idx := strings.Index(value, "@"); idx >= 0 {
		host = value[idx+1:]
	}
	return p.matchString(host)
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
// when modified. Calls onReload with a LoadResult indicating success or failure.
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

	config := &PolicyConfig{}

	data, err := os.ReadFile(p.path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("policy: no config at %s, defaulting to confirm-all", p.path)
			p.config = config
			p.defaultAction = Confirm
			p.rules = nil
			p.activeVersion = time.Time{}
			p.configSHA256 = ""
			p.configContent = ""
			resolveBins()
			mergedAgents := mergeCodingAgents(nil)
			codingAgentHeuristicsVal.Store(&codingAgentHeuristics{agents: mergedAgents})
			envVarsCaptureListVal.Store(computeEnvVarsToCapture(config, mergedAgents))
			return LoadResult{OK: true}
		}
		// Read error (EPERM, etc.) — keep previous valid config
		log.Printf("policy: read %s: %v (keeping previous)", p.path, err)
		return LoadResult{OK: false, Errors: []string{err.Error()}}
	}

	// Pre-parse into node tree to extract line numbers for error reporting.
	// This is a lightweight pass; the strict decode below does the real validation.
	ruleLines := extractRuleLines(data)

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(config); err != nil {
		errMsg := sanitizeYAMLError(err.Error())
		log.Printf("policy: %s: %s (keeping previous)", p.path, errMsg)
		badHash := sha256.Sum256(data)
		return LoadResult{
			OK:           false,
			Errors:       []string{errMsg},
			BadConfigSHA: fmt.Sprintf("%x", badHash),
			BadContent:   string(data),
		}
	}

	// Require default_action to prevent accidental allow-all policies.
	// Without a policy file, the proxy defaults to confirm-all (safe).
	// A policy file that omits default_action would silently default to allow,
	// which is a dangerous footgun — reject it with a clear error.
	if config.DefaultAction == "" {
		errMsg := "default_action is required (set to allow, deny, or confirm)"
		log.Printf("policy: %s: %s (keeping previous)", p.path, errMsg)
		badHash := sha256.Sum256(data)
		return LoadResult{
			OK:           false,
			Errors:       []string{errMsg},
			BadConfigSHA: fmt.Sprintf("%x", badHash),
			BadContent:   string(data),
		}
	}

	defaultAction, err := parseAction(config.DefaultAction)
	if err != nil {
		errMsg := fmt.Sprintf("invalid default_action: %s", err)
		log.Printf("policy: %s: %s (keeping previous)", p.path, errMsg)
		badHash := sha256.Sum256(data)
		return LoadResult{
			OK:           false,
			Errors:       []string{errMsg},
			BadConfigSHA: fmt.Sprintf("%x", badHash),
			BadContent:   string(data),
		}
	}

	var rules []compiledRule
	var compileErrors []string
	for i, r := range config.Rules {
		name := r.Name
		if name == "" {
			name = fmt.Sprintf("rule-%d", i)
		}
		linePrefix := ""
		if i < len(ruleLines) {
			linePrefix = fmt.Sprintf("line %d: ", ruleLines[i])
		}
		action, err := parseAction(r.Action)
		if err != nil {
			compileErrors = append(compileErrors, fmt.Sprintf("%srule %d (%s): invalid action %q (expected allow, deny, or confirm)", linePrefix, i, name, r.Action))
			continue
		}
		match, err := compileMatch(r.Match)
		if err != nil {
			compileErrors = append(compileErrors, fmt.Sprintf("%srule %d (%s): %v", linePrefix, i, name, err))
			continue
		}
		rules = append(rules, compiledRule{
			name:   name,
			action: action,
			match:  match,
		})
	}
	// Check for shadowed ssh_dest rules: a user@host rule after a blanket
	// host rule will never match because the hostname-only rule matches first.
	compileErrors = append(compileErrors, checkSSHDestShadowing(config.Rules, rules, ruleLines)...)

	if len(compileErrors) > 0 {
		log.Printf("policy: %s: %d compile error(s) (keeping previous)", p.path, len(compileErrors))
		for _, e := range compileErrors {
			log.Printf("  %s", e)
		}
		badHash := sha256.Sum256(data)
		return LoadResult{
			OK:           false,
			Errors:       compileErrors,
			BadConfigSHA: fmt.Sprintf("%x", badHash),
			BadContent:   string(data),
		}
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

	// Merge coding agent heuristics (builtin + config) and store atomically
	mergedAgents := mergeCodingAgents(config.CodingAgents)
	codingAgentHeuristicsVal.Store(&codingAgentHeuristics{agents: mergedAgents})

	// Compute and store the merged env var capture list
	envVarsCaptureListVal.Store(computeEnvVarsToCapture(config, mergedAgents))

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

	// Rate limiting
	if c.MaxPending != nil {
		cfg.MaxPending = *c.MaxPending
	}

	return cfg
}

func compileMatch(m MatchSpec) (compiledMatch, error) {
	var errs []string
	compile := func(field, s string) *matchPattern {
		p, err := compilePattern(s)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", field, err))
		}
		return p
	}
	cm := compiledMatch{
		processName:       m.ProcessName,
		parentProcessName: m.ParentProcessName,
		ancestor:          m.Ancestor,
		command:           compile("command", m.Command),
		sshDest:           compile("ssh_dest", m.SSHDest),
		isInKnownHosts:    m.IsInKnownHosts,
		forwardedVia:      compile("forwarded_via", m.ForwardedVia),
		isForwarded:       m.IsForwarded,
		key:               m.Key,
		cwd:               compile("cwd", m.CWD),
		tmuxWindow:        compile("tmux_window", m.TmuxWindow),
		isInContainer:     m.IsInContainer,
		isCodingAgent:     m.IsCodingAgent,
		env:               m.Env,
	}
	if len(errs) > 0 {
		return cm, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return cm, nil
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
	if !matchSSHDest(m.sshDest, sshDest) {
		return false
	}

	// is_in_known_hosts: session-bind destination resolved against known_hosts
	if m.isInKnownHosts != nil {
		sessionDest := ""
		if session != nil {
			sessionDest = session.DestHostname
		}
		if *m.isInKnownHosts {
			// true: require the dest to be known (non-empty hostname from known_hosts)
			if sessionDest == "" {
				return false
			}
		} else {
			// false: match when dest is NOT in known_hosts (no session-bind or empty hostname)
			if sessionDest != "" {
				return false
			}
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

	// is_coding_agent: bool against CallerContext.IsCodingAgent
	if m.isCodingAgent != nil {
		if *m.isCodingAgent != ctx.IsCodingAgent {
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
// Used by --check output and deny forensics logs.
type RuleCheckResult struct {
	Name       string   `yaml:"name"`
	Action     string   `yaml:"action"`
	Matched    bool     `yaml:"matched"`
	Mismatches []string `yaml:"mismatches,omitempty"`
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
	if !matchSSHDest(m.sshDest, sshDest) {
		mm = append(mm, fmt.Sprintf("ssh_dest: want %q, got %q", m.sshDest.raw, sshDest))
	}
	if m.isInKnownHosts != nil {
		sessionDest := ""
		if session != nil {
			sessionDest = session.DestHostname
		}
		if *m.isInKnownHosts {
			if sessionDest == "" {
				mm = append(mm, "is_in_known_hosts: want true, no session-bind dest")
			}
		} else {
			if sessionDest != "" {
				mm = append(mm, fmt.Sprintf("is_in_known_hosts: want false, but dest %q is in known_hosts", sessionDest))
			}
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
	if m.isCodingAgent != nil && *m.isCodingAgent != ctx.IsCodingAgent {
		mm = append(mm, fmt.Sprintf("is_coding_agent: want %v, got %v", *m.isCodingAgent, ctx.IsCodingAgent))
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

// checkSSHDestShadowing detects user@host rules that are shadowed by an
// earlier hostname-only rule. Because patterns without @ match the hostname
// portion, a rule like ssh_dest: "github.com" will match "git@github.com"
// before a later ssh_dest: "git@github.com" rule ever fires.
func checkSSHDestShadowing(yamlRules []Rule, compiled []compiledRule, ruleLines []int) []string {
	var warnings []string

	// Build a list of hostname-only ssh_dest patterns (no @) and their indices
	type hostRule struct {
		index   int
		name    string
		pattern string // the raw pattern (no @)
	}
	var hostRules []hostRule

	for i, r := range compiled {
		if r.match.sshDest == nil {
			continue
		}
		raw := r.match.sshDest.raw
		if !strings.Contains(raw, "@") {
			hostRules = append(hostRules, hostRule{i, r.name, raw})
		}
	}

	// For each user@host rule, check if an earlier hostname-only rule shadows it
	for i, r := range compiled {
		if r.match.sshDest == nil {
			continue
		}
		raw := r.match.sshDest.raw
		if !strings.Contains(raw, "@") {
			continue // not a user@host pattern
		}

		// Extract hostname from the user@host pattern
		atIdx := strings.Index(raw, "@")
		if atIdx < 0 {
			continue
		}
		host := raw[atIdx+1:]

		// Check if any earlier hostname-only rule would match this hostname.
		// Only check rules that ONLY differ in ssh_dest — if the earlier rule
		// has other match fields, it might not shadow this one.
		for _, hr := range hostRules {
			if hr.index >= i {
				break // only check earlier rules
			}
			// Check if the earlier rule's ssh_dest pattern matches our hostname.
			// For exact match: hr.pattern == host
			// For globs/regex: use the matchPattern
			earlier := compiled[hr.index]
			if earlier.match.sshDest.matchString(host) && onlyDiffersInSSHDest(earlier.match, r.match) {
				linePrefix := ""
				if i < len(ruleLines) {
					linePrefix = fmt.Sprintf("line %d: ", ruleLines[i])
				}
				warnings = append(warnings, fmt.Sprintf(
					"%srule %d (%s) ssh_dest %q is shadowed by earlier rule %d (%s) ssh_dest %q — the earlier rule matches the hostname without the user prefix, so this rule will never fire. Move the more specific rule first.",
					linePrefix, i, r.name, raw, hr.index, hr.name, hr.pattern,
				))
			}
		}
	}
	return warnings
}

// onlyDiffersInSSHDest returns true if two compiled matches have the same
// fields except for sshDest. Used by shadowing detection — if the earlier
// rule has additional match constraints, it may not actually shadow the later rule.
func onlyDiffersInSSHDest(a, b compiledMatch) bool {
	if len(a.processName) != 0 || len(b.processName) != 0 {
		return false
	}
	if len(a.parentProcessName) != 0 || len(b.parentProcessName) != 0 {
		return false
	}
	if len(a.ancestor) != 0 || len(b.ancestor) != 0 {
		return false
	}
	if a.command != nil || b.command != nil {
		return false
	}
	if a.isInKnownHosts != nil || b.isInKnownHosts != nil {
		return false
	}
	if a.forwardedVia != nil || b.forwardedVia != nil {
		return false
	}
	if a.isForwarded != nil || b.isForwarded != nil {
		return false
	}
	if a.key != "" || b.key != "" {
		return false
	}
	if a.cwd != nil || b.cwd != nil {
		return false
	}
	if a.tmuxWindow != nil || b.tmuxWindow != nil {
		return false
	}
	if a.isInContainer != nil || b.isInContainer != nil {
		return false
	}
	if a.isCodingAgent != nil || b.isCodingAgent != nil {
		return false
	}
	if len(a.env) != 0 || len(b.env) != 0 {
		return false
	}
	return true
}

func defaultPolicyPath() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "ssh-ag", "policy.yaml")
	}
	return filepath.Join(os.Getenv("HOME"), ".config", "ssh-ag", "policy.yaml")
}

// mergeCodingAgents merges builtin coding agent heuristics with user config.
// User config is additive: new agents are added, existing agents get their
// env and ancestor lists extended.
func mergeCodingAgents(userAgents map[string]CodingAgentYAML) map[string]CodingAgentYAML {
	merged := make(map[string]CodingAgentYAML, len(builtinCodingAgents)+len(userAgents))
	for name, h := range builtinCodingAgents {
		merged[name] = CodingAgentYAML{
			Env:       copyMap(h.Env),
			Ancestors: append([]string(nil), h.Ancestors...),
		}
	}
	for name, h := range userAgents {
		existing, ok := merged[name]
		if !ok {
			merged[name] = CodingAgentYAML{
				Env:       copyMap(h.Env),
				Ancestors: append([]string(nil), h.Ancestors...),
			}
			continue
		}
		for k, v := range h.Env {
			if existing.Env == nil {
				existing.Env = make(map[string]string)
			}
			existing.Env[k] = v
		}
		existing.Ancestors = append(existing.Ancestors, h.Ancestors...)
		merged[name] = existing
	}
	return merged
}

func copyMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	cp := make(map[string]string, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

// computeEnvVarsToCapture returns the deduplicated set of env var names to
// read from /proc/pid/environ. Sources: builtins + capture_extra_env_vars +
// coding_agents env keys + rule match.env keys.
func computeEnvVarsToCapture(config *PolicyConfig, mergedAgents map[string]CodingAgentYAML) []string {
	seen := make(map[string]bool)
	var result []string
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			result = append(result, name)
		}
	}

	// Built-in defaults
	for _, name := range builtinEnvVars {
		add(name)
	}

	if config == nil {
		sort.Strings(result)
		return result
	}

	// Config capture_extra_env_vars
	for _, name := range config.CaptureExtraEnv {
		add(name)
	}

	// Coding agent env keys
	for _, h := range mergedAgents {
		for name := range h.Env {
			add(name)
		}
	}

	// Rule match.env keys
	for _, r := range config.Rules {
		for name := range r.Match.Env {
			add(name)
		}
	}

	sort.Strings(result)
	return result
}
