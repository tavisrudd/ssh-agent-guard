package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	yamlv3 "gopkg.in/yaml.v3"
)

func boolPtr(b bool) *bool { return &b }

// newTestPolicyFromFile creates a Policy from a file, discarding the LoadResult.
func newTestPolicyFromFile(path string) *Policy {
	p, _ := NewPolicy(path)
	return p
}

func TestParseAction(t *testing.T) {
	tests := []struct {
		input   string
		want    Action
		wantErr bool
	}{
		{"allow", Allow, false},
		{"Allow", Allow, false},
		{"ALLOW", Allow, false},
		{"deny", Deny, false},
		{"confirm", Confirm, false},
		{"bogus", Deny, true},
		{"", Deny, true},
	}
	for _, tt := range tests {
		got, err := parseAction(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseAction(%q): err=%v, wantErr=%v", tt.input, err, tt.wantErr)
		}
		if got != tt.want {
			t.Errorf("parseAction(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestActionString(t *testing.T) {
	if Allow.String() != "allow" {
		t.Errorf("Allow.String() = %q", Allow.String())
	}
	if Deny.String() != "deny" {
		t.Errorf("Deny.String() = %q", Deny.String())
	}
	if Confirm.String() != "confirm" {
		t.Errorf("Confirm.String() = %q", Confirm.String())
	}
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern, value string
		want           bool
	}{
		// Exact match
		{"foo", "foo", true},
		{"foo", "bar", false},
		// Star wildcard
		{"*", "anything", true},
		{"*", "", true},
		{"foo*", "foobar", true},
		{"foo*", "foo", true},
		{"foo*", "fo", false},
		{"*bar", "foobar", true},
		{"*bar", "bar", true},
		{"*bar", "bars", false},
		{"f*r", "foobar", true},
		{"f*r", "fr", true},
		{"f*r", "f", false},
		// Question mark
		{"fo?", "foo", true},
		{"fo?", "fo", false},
		{"fo?", "fooo", false},
		{"?", "x", true},
		{"?", "", false},
		// Combined
		{"*.example.com", "foo.example.com", true},
		{"*.example.com", "example.com", false},
		{"git@*", "git@github.com", true},
		{"*@*", "user@host", true},
		// Consecutive stars
		{"**", "anything", true},
		{"f**r", "foobar", true},
		// Empty
		{"", "", true},
		{"", "x", false},
	}
	for _, tt := range tests {
		got := globMatch(tt.pattern, tt.value)
		if got != tt.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
		}
	}
}

func TestCompilePattern(t *testing.T) {
	// Nil for empty string
	p, err := compilePattern("")
	if p != nil || err != nil {
		t.Error("compilePattern(\"\") should be nil with no error")
	}

	// Glob pattern
	p, err = compilePattern("foo*")
	if err != nil {
		t.Fatalf("compilePattern(\"foo*\") error: %v", err)
	}
	if p == nil || p.regex != nil {
		t.Error("compilePattern(\"foo*\") should be glob")
	}
	if !p.matchString("foobar") {
		t.Error("foo* should match foobar")
	}

	// Regex pattern (~ prefix)
	p, err = compilePattern("~^ssh-.*$")
	if err != nil {
		t.Fatalf("compilePattern(\"~^ssh-.*$\") error: %v", err)
	}
	if p == nil || p.regex == nil {
		t.Error("compilePattern(\"~^ssh-.*$\") should be regex")
	}
	if !p.matchString("ssh-keygen") {
		t.Error("~^ssh-.*$ should match ssh-keygen")
	}
	if p.matchString("git") {
		t.Error("~^ssh-.*$ should not match git")
	}

	// Invalid regex returns an error
	_, err = compilePattern("~[invalid")
	if err == nil {
		t.Error("compilePattern with invalid regex should return error")
	}
}

func TestMatchPatternNilWildcard(t *testing.T) {
	var p *matchPattern
	if !p.matchString("anything") {
		t.Error("nil matchPattern should match anything (wildcard)")
	}
}

// TestPolicyEvaluate tests the full policy evaluation pipeline with YAML configs.
func TestPolicyEvaluate(t *testing.T) {
	tests := []struct {
		name       string
		yaml       string
		caller     *CallerContext
		session    *SessionBindInfo
		keyFP      string
		wantAction Action
		wantRule   string
	}{
		{
			name: "default allow with no rules",
			yaml: "default_action: allow\nrules: []\n",
			caller: &CallerContext{
				Name: "ssh", Env: map[string]string{},
			},
			wantAction: Allow,
			wantRule:   "default",
		},
		{
			name: "default deny",
			yaml: "default_action: deny\nrules: []\n",
			caller: &CallerContext{
				Name: "ssh", Env: map[string]string{},
			},
			wantAction: Deny,
			wantRule:   "default",
		},
		{
			name: "first match wins",
			yaml: `
default_action: deny
rules:
  - name: first
    match:
      process_name: ssh
    action: allow
  - name: second
    match:
      process_name: ssh
    action: deny
`,
			caller: &CallerContext{
				Name: "ssh", Env: map[string]string{},
			},
			wantAction: Allow,
			wantRule:   "first",
		},
		{
			name: "process_name match with list",
			yaml: `
default_action: deny
rules:
  - name: git-callers
    match:
      process_name: [git, git-remote-https]
    action: allow
`,
			caller: &CallerContext{
				Name: "git-remote-https", Env: map[string]string{},
			},
			wantAction: Allow,
			wantRule:   "git-callers",
		},
		{
			name: "process_name list no match",
			yaml: `
default_action: deny
rules:
  - name: git-callers
    match:
      process_name: [git, git-remote-https]
    action: allow
`,
			caller: &CallerContext{
				Name: "ssh", Env: map[string]string{},
			},
			wantAction: Deny,
			wantRule:   "default",
		},
		{
			name: "parent_process_name match",
			yaml: `
default_action: deny
rules:
  - name: git-parent
    match:
      parent_process_name: git
    action: allow
`,
			caller: &CallerContext{
				Name: "ssh",
				Ancestry: []AncestorInfo{
					{PID: 100, Name: "ssh"},
					{PID: 50, Name: "git"},
					{PID: 10, Name: "bash"},
				},
				Env: map[string]string{},
			},
			wantAction: Allow,
			wantRule:   "git-parent",
		},
		{
			name: "parent_process_name no match",
			yaml: `
default_action: allow
rules:
  - name: git-parent
    match:
      parent_process_name: git
    action: deny
`,
			caller: &CallerContext{
				Name: "ssh",
				Ancestry: []AncestorInfo{
					{PID: 100, Name: "ssh"},
					{PID: 50, Name: "bash"},
					{PID: 10, Name: "git"},  // grandparent, not parent
				},
				Env: map[string]string{},
			},
			wantAction: Allow,
			wantRule:   "default",
		},
		{
			name: "parent_process_name with no ancestry",
			yaml: `
default_action: allow
rules:
  - name: git-parent
    match:
      parent_process_name: git
    action: deny
`,
			caller: &CallerContext{
				Name: "ssh",
				Ancestry: []AncestorInfo{
					{PID: 100, Name: "ssh"},
				},
				Env: map[string]string{},
			},
			wantAction: Allow,
			wantRule:   "default",
		},
		{
			name: "ssh_dest glob",
			yaml: `
default_action: deny
rules:
  - name: github
    match:
      ssh_dest: "git@github.com"
    action: allow
`,
			caller: &CallerContext{
				Name: "ssh", SSHDest: "git@github.com", Env: map[string]string{},
			},
			wantAction: Allow,
			wantRule:   "github",
		},
		{
			name: "is_forwarded bool match",
			yaml: `
default_action: allow
rules:
  - name: block-forwarded
    match:
      is_forwarded: true
    action: deny
`,
			caller: &CallerContext{
				Name: "ssh", Env: map[string]string{},
			},
			session:    &SessionBindInfo{IsForwarded: true},
			wantAction: Deny,
			wantRule:   "block-forwarded",
		},
		{
			name: "is_forwarded false when no session",
			yaml: `
default_action: allow
rules:
  - name: direct-only
    match:
      is_forwarded: false
    action: confirm
`,
			caller: &CallerContext{
				Name: "ssh", Env: map[string]string{},
			},
			session:    nil,
			wantAction: Confirm,
			wantRule:   "direct-only",
		},
		{
			name: "key prefix match",
			yaml: `
default_action: deny
rules:
  - name: my-key
    match:
      key: "SHA256:abc123"
    action: allow
`,
			caller: &CallerContext{
				Name: "ssh", Env: map[string]string{},
			},
			keyFP:      "SHA256:abc123def456",
			wantAction: Allow,
			wantRule:   "my-key",
		},
		{
			name: "key prefix no match",
			yaml: `
default_action: allow
rules:
  - name: my-key
    match:
      key: "SHA256:abc123"
    action: deny
`,
			caller: &CallerContext{
				Name: "ssh", Env: map[string]string{},
			},
			keyFP:      "SHA256:xyz789",
			wantAction: Allow,
			wantRule:   "default",
		},
		{
			name: "env match",
			yaml: `
default_action: allow
rules:
  - name: claude-confirm
    match:
      env:
        CLAUDECODE: "1"
    action: confirm
`,
			caller: &CallerContext{
				Name: "ssh",
				Env:  map[string]string{"CLAUDECODE": "1"},
			},
			wantAction: Confirm,
			wantRule:   "claude-confirm",
		},
		{
			name: "env no match",
			yaml: `
default_action: allow
rules:
  - name: claude-confirm
    match:
      env:
        CLAUDECODE: "1"
    action: confirm
`,
			caller: &CallerContext{
				Name: "ssh",
				Env:  map[string]string{},
			},
			wantAction: Allow,
			wantRule:   "default",
		},
		{
			name: "ancestor match",
			yaml: `
default_action: deny
rules:
  - name: via-tmux
    match:
      ancestor: tmux
    action: allow
`,
			caller: &CallerContext{
				Name: "ssh",
				Ancestry: []AncestorInfo{
					{PID: 100, Name: "ssh"},
					{PID: 50, Name: "bash"},
					{PID: 10, Name: "tmux"},
				},
				Env: map[string]string{},
			},
			wantAction: Allow,
			wantRule:   "via-tmux",
		},
		{
			name: "ancestor list match",
			yaml: `
default_action: deny
rules:
  - name: shell-ancestor
    match:
      ancestor: [bash, zsh, fish]
    action: allow
`,
			caller: &CallerContext{
				Name: "ssh",
				Ancestry: []AncestorInfo{
					{PID: 100, Name: "ssh"},
					{PID: 50, Name: "zsh"},
				},
				Env: map[string]string{},
			},
			wantAction: Allow,
			wantRule:   "shell-ancestor",
		},
		{
			name: "command regex match",
			yaml: `
default_action: deny
rules:
  - name: ssh-to-local
    match:
      command: "~ssh.*\\.local"
    action: allow
`,
			caller: &CallerContext{
				Name:    "ssh",
				Cmdline: "ssh alice@nano.local",
				Env:     map[string]string{},
			},
			wantAction: Allow,
			wantRule:   "ssh-to-local",
		},
		{
			name: "cwd glob match",
			yaml: `
default_action: deny
rules:
  - name: from-src
    match:
      cwd: "/home/alice/src/*"
    action: allow
`,
			caller: &CallerContext{
				Name: "ssh",
				CWD:  "/home/alice/src/myproject",
				Env:  map[string]string{},
			},
			wantAction: Allow,
			wantRule:   "from-src",
		},
		{
			name: "ssh_dest from session-bind fallback",
			yaml: `
default_action: deny
rules:
  - name: known-remote
    match:
      ssh_dest: "*.example.com"
    action: allow
`,
			caller: &CallerContext{
				Name: "ssh", Env: map[string]string{},
			},
			session: &SessionBindInfo{
				DestHostname: "box.example.com",
			},
			wantAction: Allow,
			wantRule:   "known-remote",
		},
		{
			name: "is_in_known_hosts with dest",
			yaml: `
default_action: deny
rules:
  - name: in-known-hosts
    match:
      is_in_known_hosts: true
    action: allow
`,
			caller: &CallerContext{
				Name: "ssh", Env: map[string]string{},
			},
			session: &SessionBindInfo{
				DestHostname: "myhost",
			},
			wantAction: Allow,
			wantRule:   "in-known-hosts",
		},
		{
			name: "is_in_known_hosts without dest",
			yaml: `
default_action: allow
rules:
  - name: in-known-hosts
    match:
      is_in_known_hosts: true
    action: deny
`,
			caller: &CallerContext{
				Name: "ssh", Env: map[string]string{},
			},
			session:    nil,
			wantAction: Allow,
			wantRule:   "default",
		},
		{
			name: "is_in_known_hosts false matches unknown host",
			yaml: `
default_action: allow
rules:
  - name: unknown-host
    match:
      is_in_known_hosts: false
    action: deny
`,
			caller: &CallerContext{
				Name: "ssh", Env: map[string]string{},
			},
			session:    nil,
			wantAction: Deny,
			wantRule:   "unknown-host",
		},
		{
			name: "is_in_known_hosts false does not match known host",
			yaml: `
default_action: allow
rules:
  - name: unknown-host
    match:
      is_in_known_hosts: false
    action: deny
`,
			caller: &CallerContext{
				Name: "ssh", Env: map[string]string{},
			},
			session: &SessionBindInfo{
				DestHostname: "known.example.com",
			},
			wantAction: Allow,
			wantRule:   "default",
		},
		{
			name: "multiple match fields AND logic",
			yaml: `
default_action: deny
rules:
  - name: claude-container
    match:
      is_in_container: true
      env:
        CLAUDECODE: "1"
    action: confirm
`,
			caller: &CallerContext{
				Name:        "ssh",
				IsContainer: true,
				Env:         map[string]string{"CLAUDECODE": "1"},
			},
			wantAction: Confirm,
			wantRule:   "claude-container",
		},
		{
			name: "multiple match fields partial mismatch",
			yaml: `
default_action: allow
rules:
  - name: claude-container
    match:
      is_in_container: true
      env:
        CLAUDECODE: "1"
    action: deny
`,
			caller: &CallerContext{
				Name:        "ssh",
				IsContainer: false, // doesn't match
				Env:         map[string]string{"CLAUDECODE": "1"},
			},
			wantAction: Allow,
			wantRule:   "default",
		},
		{
			name: "is_in_container match true",
			yaml: `
default_action: allow
rules:
  - name: container-confirm
    match:
      is_in_container: true
    action: confirm
`,
			caller: &CallerContext{
				Name: "ssh", IsContainer: true, Env: map[string]string{},
			},
			wantAction: Confirm,
			wantRule:   "container-confirm",
		},
		{
			name: "is_in_container match false",
			yaml: `
default_action: deny
rules:
  - name: host-allow
    match:
      is_in_container: false
    action: allow
`,
			caller: &CallerContext{
				Name: "ssh", IsContainer: false, Env: map[string]string{},
			},
			wantAction: Allow,
			wantRule:   "host-allow",
		},
		{
			name: "is_in_container no match when not in container",
			yaml: `
default_action: allow
rules:
  - name: container-deny
    match:
      is_in_container: true
    action: deny
`,
			caller: &CallerContext{
				Name: "ssh", IsContainer: false, Env: map[string]string{},
			},
			wantAction: Allow,
			wantRule:   "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			policyFile := filepath.Join(dir, "policy.yaml")
			if err := os.WriteFile(policyFile, []byte(tt.yaml), 0644); err != nil {
				t.Fatal(err)
			}

			policy := newTestPolicyFromFile(policyFile)
			result := policy.Evaluate(tt.caller, tt.session, tt.keyFP)

			if result.Action != tt.wantAction {
				t.Errorf("action = %v, want %v", result.Action, tt.wantAction)
			}
			if result.RuleName != tt.wantRule {
				t.Errorf("rule = %q, want %q", result.RuleName, tt.wantRule)
			}
		})
	}
}

func TestPolicyLoadMissingFile(t *testing.T) {
	policy, _ := NewPolicy("/nonexistent/policy.yaml")
	result := policy.Evaluate(
		&CallerContext{Name: "ssh", Env: map[string]string{}},
		nil, "",
	)
	if result.Action != Confirm {
		t.Errorf("missing policy file should default to confirm, got %v", result.Action)
	}

	// Config status: missing file is not an error condition
	cs := policy.ConfigStatus()
	if !cs.IsCurrentVersion {
		t.Error("missing file should be considered current (expected state)")
	}
	if cs.ActiveVersion != "" {
		t.Errorf("missing file should have empty active_version, got %q", cs.ActiveVersion)
	}
}

func TestPolicyLoadInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")

	// Write valid policy first
	valid := "default_action: deny\nrules: []\n"
	os.WriteFile(policyFile, []byte(valid), 0644)
	policy := newTestPolicyFromFile(policyFile)

	// Verify deny is loaded
	result := policy.Evaluate(
		&CallerContext{Name: "ssh", Env: map[string]string{}},
		nil, "",
	)
	if result.Action != Deny {
		t.Fatal("expected deny after valid load")
	}

	// After successful load: should be current, have a version
	cs := policy.ConfigStatus()
	if !cs.IsCurrentVersion {
		t.Error("should be current after successful load")
	}
	if cs.ActiveVersion == "" {
		t.Error("should have active_version after successful load")
	}

	// Overwrite with invalid YAML — should keep previous config
	// Sleep to ensure mtime differs (ConfigStatus uses mtime to detect staleness)
	time.Sleep(10 * time.Millisecond)
	os.WriteFile(policyFile, []byte("{{{{invalid"), 0644)
	loadResult := policy.Load()

	if loadResult.OK {
		t.Error("load of invalid YAML should return OK=false")
	}
	if len(loadResult.Errors) == 0 {
		t.Error("load of invalid YAML should return errors")
	}
	if loadResult.BadConfigSHA == "" {
		t.Error("load of invalid YAML should return bad config SHA")
	}
	if loadResult.BadContent != "{{{{invalid" {
		t.Errorf("load of invalid YAML should return bad content, got %q", loadResult.BadContent)
	}

	result = policy.Evaluate(
		&CallerContext{Name: "ssh", Env: map[string]string{}},
		nil, "",
	)
	if result.Action != Deny {
		t.Errorf("invalid YAML reload should keep previous config, got %v", result.Action)
	}

	// After failed reload: not current (mtime changed), keeps old version
	cs = policy.ConfigStatus()
	if cs.IsCurrentVersion {
		t.Error("should NOT be current after failed reload")
	}

	// Fix the YAML — should update version
	os.WriteFile(policyFile, []byte("default_action: allow\nrules: []\n"), 0644)
	loadResult = policy.Load()

	if !loadResult.OK {
		t.Error("load of valid YAML should return OK=true")
	}

	cs = policy.ConfigStatus()
	if !cs.IsCurrentVersion {
		t.Error("should be current after successful reload")
	}
}

func TestPolicyConfigStatusStaleOnDiskChange(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")

	os.WriteFile(policyFile, []byte("default_action: deny\nrules: []\n"), 0644)
	policy := newTestPolicyFromFile(policyFile)

	// Immediately after load, should be current
	cs := policy.ConfigStatus()
	if !cs.IsCurrentVersion {
		t.Error("should be current immediately after load")
	}

	// Modify the file on disk without calling Load() — simulates fsnotify lag
	// Sleep briefly to ensure mtime differs (filesystem granularity)
	time.Sleep(10 * time.Millisecond)
	os.WriteFile(policyFile, []byte("default_action: allow\nrules: []\n"), 0644)

	cs = policy.ConfigStatus()
	if cs.IsCurrentVersion {
		t.Error("should NOT be current after file changed on disk without reload")
	}

	// Reload picks up the new version
	_ = policy.Load()
	cs = policy.ConfigStatus()
	if !cs.IsCurrentVersion {
		t.Error("should be current after reload")
	}
}

func TestSyncErrorFile(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	errorFile := filepath.Join(dir, "config_error.yaml")

	// Valid config — no error file
	os.WriteFile(policyFile, []byte("default_action: deny\nrules: []\n"), 0644)
	policy, result := NewPolicy(policyFile)
	syncErrorFile(errorFile, result)
	if _, err := os.Stat(errorFile); !os.IsNotExist(err) {
		t.Error("error file should not exist after valid load")
	}

	// Break the config — error file should appear
	os.WriteFile(policyFile, []byte("{{broken"), 0644)
	result = policy.Load()
	syncErrorFile(errorFile, result)
	data, err := os.ReadFile(errorFile)
	if err != nil {
		t.Fatal("error file should exist after failed load")
	}
	// Verify error file is valid YAML and contains readable errors
	var parsed struct {
		Errors []string `yaml:"errors"`
	}
	if err := yamlv3.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("error file is not valid YAML: %v\ncontents: %s", err, data)
	}
	if len(parsed.Errors) == 0 {
		t.Errorf("error file should contain errors, got: %s", data)
	}

	// Fix the config — error file should be removed
	os.WriteFile(policyFile, []byte("default_action: allow\nrules: []\n"), 0644)
	result = policy.Load()
	syncErrorFile(errorFile, result)
	if _, err := os.Stat(errorFile); !os.IsNotExist(err) {
		t.Error("error file should be removed after successful reload")
	}
}

func TestPolicyEvaluateVerbose(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	yaml := `
default_action: deny
rules:
  - name: github
    match:
      ssh_dest: "git@github.com"
    action: allow
  - name: container-confirm
    match:
      is_in_container: true
    action: confirm
`
	os.WriteFile(policyFile, []byte(yaml), 0644)
	policy := newTestPolicyFromFile(policyFile)

	caller := &CallerContext{
		Name:        "ssh",
		SSHDest:     "git@github.com",
		IsContainer: true,
		Env:         map[string]string{},
	}

	results := policy.EvaluateVerbose(caller, nil, "")

	if len(results) != 2 {
		t.Fatalf("expected 2 rule results, got %d", len(results))
	}

	// First rule should match
	if !results[0].Matched {
		t.Errorf("github rule should match, mismatches: %v", results[0].Mismatches)
	}
	if results[0].Name != "github" {
		t.Errorf("first rule name = %q, want github", results[0].Name)
	}

	// Second rule should also match (both conditions true)
	if !results[1].Matched {
		t.Errorf("container-confirm rule should match, mismatches: %v", results[1].Mismatches)
	}
}

func TestPolicyEvaluateVerboseMismatches(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	yaml := `
default_action: allow
rules:
  - name: test
    match:
      process_name: git
      ssh_dest: "git@github.com"
      is_in_container: true
    action: deny
`
	os.WriteFile(policyFile, []byte(yaml), 0644)
	policy := newTestPolicyFromFile(policyFile)

	caller := &CallerContext{
		Name:        "ssh",       // won't match "git"
		SSHDest:     "user@host", // won't match
		IsContainer: false,       // won't match
		Env:                map[string]string{},
	}

	results := policy.EvaluateVerbose(caller, nil, "")
	if len(results) != 1 {
		t.Fatal("expected 1 result")
	}
	if results[0].Matched {
		t.Error("should not match")
	}
	if len(results[0].Mismatches) != 3 {
		t.Errorf("expected 3 mismatches, got %d: %v", len(results[0].Mismatches), results[0].Mismatches)
	}
}

func TestPolicyLoadBadRegexRejectsConfig(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")

	// Load valid config first
	valid := "default_action: deny\nrules:\n  - name: good\n    match:\n      ssh_dest: \"*.example.com\"\n    action: allow\n"
	os.WriteFile(policyFile, []byte(valid), 0644)
	policy := newTestPolicyFromFile(policyFile)

	// Verify it loaded
	result := policy.Evaluate(
		&CallerContext{Name: "ssh", SSHDest: "foo.example.com", Env: map[string]string{}},
		nil, "",
	)
	if result.Action != Allow {
		t.Fatal("valid config should allow foo.example.com")
	}

	// Overwrite with bad regex — should keep previous config
	bad := "default_action: allow\nrules:\n  - name: broken\n    match:\n      ssh_dest: \"~[invalid\"\n    action: deny\n"
	os.WriteFile(policyFile, []byte(bad), 0644)
	loadResult := policy.Load()

	if loadResult.OK {
		t.Error("config with bad regex should fail to load")
	}
	if len(loadResult.Errors) == 0 {
		t.Error("should report compile errors")
	}
	if loadResult.BadConfigSHA == "" {
		t.Error("should include bad config SHA")
	}

	// Previous config still active
	result = policy.Evaluate(
		&CallerContext{Name: "ssh", SSHDest: "foo.example.com", Env: map[string]string{}},
		nil, "",
	)
	if result.Action != Allow {
		t.Errorf("should keep previous config after bad regex, got %v", result.Action)
	}
}

func TestPolicyLoadUnknownFieldRejectsConfig(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")

	// Typo in field name: "proccess_name" instead of "process_name"
	bad := "default_action: deny\nrules:\n  - name: typo\n    match:\n      proccess_name: ssh\n    action: allow\n"
	os.WriteFile(policyFile, []byte(bad), 0644)
	_, loadResult := NewPolicy(policyFile)

	if loadResult.OK {
		t.Error("config with unknown field should fail to load")
	}
	if len(loadResult.Errors) == 0 {
		t.Error("should report parse error for unknown field")
	}
}

func TestPolicyLoadBadDefaultActionRejectsConfig(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")

	valid := "default_action: deny\nrules: []\n"
	os.WriteFile(policyFile, []byte(valid), 0644)
	policy := newTestPolicyFromFile(policyFile)

	// Overwrite with typo in default_action
	bad := "default_action: alow\nrules: []\n"
	os.WriteFile(policyFile, []byte(bad), 0644)
	loadResult := policy.Load()

	if loadResult.OK {
		t.Error("config with bad default_action should fail to load")
	}

	// Previous config still active (deny, not the broken "alow")
	result := policy.Evaluate(
		&CallerContext{Name: "ssh", Env: map[string]string{}},
		nil, "",
	)
	if result.Action != Deny {
		t.Errorf("should keep previous config after bad default_action, got %v", result.Action)
	}
}
