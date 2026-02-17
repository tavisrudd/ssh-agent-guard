package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func secondsToDuration(s int) time.Duration {
	return time.Duration(s) * time.Second
}

func TestReadExePath(t *testing.T) {
	path := readExePath(int32(os.Getpid()))
	if path == "" {
		t.Fatal("readExePath returned empty for own PID")
	}
	// Should be an absolute path
	if !strings.HasPrefix(path, "/") {
		t.Errorf("readExePath returned non-absolute path: %q", path)
	}

	// Non-existent PID should return empty
	if got := readExePath(999999999); got != "" {
		t.Errorf("readExePath for non-existent PID = %q, want empty", got)
	}
}

func TestReadProcessAge(t *testing.T) {
	age := readProcessAge(int32(os.Getpid()))
	if age <= 0 {
		t.Fatalf("readProcessAge returned %v for own PID, want positive", age)
	}

	// Non-existent PID should return 0
	if got := readProcessAge(999999999); got != 0 {
		t.Errorf("readProcessAge for non-existent PID = %v, want 0", got)
	}
}

func TestFormatAge(t *testing.T) {
	tests := []struct {
		name string
		secs int
		want string
	}{
		{"seconds", 3, "3s"},
		{"one minute", 60, "1m"},
		{"minutes and seconds", 135, "2m15s"},
		{"one hour", 3600, "1h"},
		{"hours and minutes", 5400, "1h30m"},
		{"one day", 86400, "1d"},
		{"days and hours", 90000, "1d1h"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatAge(secondsToDuration(tt.secs))
			if got != tt.want {
				t.Errorf("formatAge(%ds) = %q, want %q", tt.secs, got, tt.want)
			}
		})
	}
}

func TestCollectDenyForensics(t *testing.T) {
	caller := &CallerContext{
		PID:  int32(os.Getpid()),
		Name: "ssh",
		Env:  map[string]string{},
	}

	// Create a simple policy with one rule
	policy := &Policy{}
	policy.defaultAction = Deny
	policy.rules = []compiledRule{
		{
			name:   "test-rule",
			action: Allow,
			match:  compiledMatch{processName: []string{"git"}},
		},
	}

	f := collectDenyForensics(caller, nil, "SHA256:test", policy, 3)
	if f == nil {
		t.Fatal("collectDenyForensics returned nil")
	}

	if f.SignRequestNum != 3 {
		t.Errorf("SignRequestNum = %d, want 3", f.SignRequestNum)
	}

	if f.ProcessAge == "" {
		t.Error("ProcessAge is empty")
	}

	if len(f.RuleTrace) != 1 {
		t.Fatalf("RuleTrace has %d entries, want 1", len(f.RuleTrace))
	}
	if f.RuleTrace[0].Name != "test-rule" {
		t.Errorf("RuleTrace[0].Name = %q, want test-rule", f.RuleTrace[0].Name)
	}
	if f.RuleTrace[0].Matched {
		t.Error("RuleTrace[0].Matched should be false (process is ssh, rule wants git)")
	}
}

func TestCollectMutationForensics(t *testing.T) {
	caller := &CallerContext{
		PID:  int32(os.Getpid()),
		Name: "ssh-add",
		Env:  map[string]string{},
	}

	f := collectMutationForensics(caller)
	if f == nil {
		t.Fatal("collectMutationForensics returned nil")
	}

	if f.ProcessAge == "" {
		t.Error("ProcessAge is empty")
	}

	// Mutations have no rule trace
	if len(f.RuleTrace) != 0 {
		t.Errorf("RuleTrace has %d entries, want 0", len(f.RuleTrace))
	}
}

func TestLogEventForensicsYAML(t *testing.T) {
	// logEvent with forensics should include forensics block
	ev := &logEvent{
		Timestamp:   "2026-02-16T10:00:00",
		Trigger:     "sign",
		ProcessName: "ssh",
		LocalPID:    1234,
		UID:         1000,
		GID:         1000,
		ExePath:     "/usr/bin/ssh",
		Decision:    "deny",
		Forensics: &DenyForensics{
			SignRequestNum: 1,
			ProcessAge:     "3s",
			RuleTrace: []RuleCheckResult{
				{
					Name:       "test-rule",
					Action:     "allow",
					Matched:    false,
					Mismatches: []string{"process_name: want [git], got \"ssh\""},
				},
			},
		},
	}

	data, err := yaml.Marshal(ev)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}

	s := string(data)
	if !strings.Contains(s, "forensics:") {
		t.Error("YAML output missing 'forensics:' key")
	}
	if !strings.Contains(s, "sign_request_num: 1") {
		t.Error("YAML output missing sign_request_num")
	}
	if !strings.Contains(s, "process_age: 3s") {
		t.Error("YAML output missing process_age")
	}
	if !strings.Contains(s, "rule_trace:") {
		t.Error("YAML output missing rule_trace")
	}
	if !strings.Contains(s, "uid: 1000") {
		t.Error("YAML output missing uid")
	}
	if !strings.Contains(s, "gid: 1000") {
		t.Error("YAML output missing gid")
	}
	if !strings.Contains(s, "exe_path: /usr/bin/ssh") {
		t.Error("YAML output missing exe_path")
	}

	// logEvent without forensics should omit the block
	ev2 := &logEvent{
		Timestamp:   "2026-02-16T10:00:00",
		Trigger:     "sign",
		ProcessName: "ssh",
		LocalPID:    1234,
		Decision:    "allow",
	}

	data2, err := yaml.Marshal(ev2)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}

	if strings.Contains(string(data2), "forensics:") {
		t.Error("YAML output for allowed event should not contain 'forensics:'")
	}
}

func TestGetBootTime(t *testing.T) {
	bt := getBootTime()
	if bt.IsZero() {
		t.Fatal("getBootTime returned zero time")
	}
}
