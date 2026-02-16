package main

import (
	"os"
	"testing"
)

func TestProcessName(t *testing.T) {
	tests := []struct {
		cmdline string
		want    string
	}{
		// Basic
		{"ssh user@host", "ssh"},
		{"/usr/bin/ssh user@host", "ssh"},
		// Nix wrapped
		{"/nix/store/abc123-ssh-9.0/.ssh-wrapped -o Foo host", "ssh"},
		{".git-wrapped", "git"},
		// Just the binary name
		{"git", "git"},
		// Empty
		{"", "unknown"},
		// Leading dot only
		{".wrapped", "wrapped"},
		// Path with no wrapping
		{"/usr/local/bin/my-tool --flag", "my-tool"},
	}
	for _, tt := range tests {
		got := processName(tt.cmdline)
		if got != tt.want {
			t.Errorf("processName(%q) = %q, want %q", tt.cmdline, got, tt.want)
		}
	}
}

func TestExtractSSHDest(t *testing.T) {
	tests := []struct {
		cmdline string
		want    string
	}{
		// Simple
		{"ssh host", "host"},
		{"ssh user@host", "user@host"},
		// With flags
		{"ssh -v user@host", "user@host"},
		{"ssh -vvv user@host", "user@host"},
		// Flags that consume next arg
		{"ssh -p 22 user@host", "user@host"},
		{"ssh -o StrictHostKeyChecking=no user@host", "user@host"},
		{"ssh -i /path/to/key user@host", "user@host"},
		{"ssh -J jump user@host", "user@host"},
		// Multiple flags
		{"ssh -v -p 22 -o Foo=bar user@host", "user@host"},
		// With command
		{"ssh user@host ls -la", "user@host"},
		// Nix-wrapped ssh
		{"/nix/store/abc123-ssh/.ssh-wrapped user@host", "user@host"},
		// Not ssh
		{"git push origin main", ""},
		{"", ""},
		// SSH with no destination
		{"ssh -v", ""},
		// Forward flags
		{"ssh -L 8080:localhost:80 user@host", "user@host"},
		{"ssh -R 9090:localhost:90 user@host", "user@host"},
		{"ssh -D 1080 user@host", "user@host"},
	}
	for _, tt := range tests {
		got := extractSSHDest(tt.cmdline)
		if got != tt.want {
			t.Errorf("extractSSHDest(%q) = %q, want %q", tt.cmdline, got, tt.want)
		}
	}
}

func TestParseMuxViaHost(t *testing.T) {
	tests := []struct {
		cmdline string
		want    string
	}{
		// Standard mux process — returns user@host
		{"ssh: /home/alice/.ssh/sockets/nano_22_alice [mux]", "alice@nano"},
		{"ssh: /tmp/sockets/host.example.com_22_user [mux]", "user@host.example.com"},
		// Not a mux process
		{"ssh user@host", ""},
		{"", ""},
		// Missing [mux] suffix
		{"ssh: /path/to/socket", ""},
		// Missing ssh: prefix
		{"/path/to/socket [mux]", ""},
	}
	for _, tt := range tests {
		got := parseMuxViaHost(tt.cmdline)
		if got != tt.want {
			t.Errorf("parseMuxViaHost(%q) = %q, want %q", tt.cmdline, got, tt.want)
		}
	}
}

func TestFindSSHDest(t *testing.T) {
	// Should find dest in self first
	ctx := &CallerContext{
		Name:    "ssh",
		Cmdline: "ssh user@myhost",
		Ancestry: []AncestorInfo{
			{Name: "ssh", Cmdline: "ssh user@myhost"},
			{Name: "bash", Cmdline: "bash"},
		},
		Env: map[string]string{},
	}
	if got := findSSHDest(ctx); got != "user@myhost" {
		t.Errorf("findSSHDest = %q, want user@myhost", got)
	}

	// Should fall back to ancestor
	ctx = &CallerContext{
		Name:    "git",
		Cmdline: "git push",
		Ancestry: []AncestorInfo{
			{Name: "git", Cmdline: "git push"},
			{Name: "ssh", Cmdline: "ssh git@github.com git-receive-pack repo"},
		},
		Env: map[string]string{},
	}
	if got := findSSHDest(ctx); got != "git@github.com" {
		t.Errorf("findSSHDest = %q, want git@github.com", got)
	}

	// No ssh in ancestry
	ctx = &CallerContext{
		Name:    "curl",
		Cmdline: "curl https://example.com",
		Ancestry: []AncestorInfo{
			{Name: "curl", Cmdline: "curl https://example.com"},
			{Name: "bash", Cmdline: "bash"},
		},
		Env: map[string]string{},
	}
	if got := findSSHDest(ctx); got != "" {
		t.Errorf("findSSHDest = %q, want empty", got)
	}
}

func TestDetectPIDNamespace(t *testing.T) {
	// Our own PID should be in our own namespace (not a container)
	ns, isContainer := detectPIDNamespace(int32(os.Getpid()))
	if isContainer {
		t.Error("own PID should not be detected as container")
	}
	if ns == "" {
		t.Error("namespace should not be empty for own PID")
	}

	// Non-existent PID should return empty, not container
	ns, isContainer = detectPIDNamespace(999999999)
	if isContainer {
		t.Error("non-existent PID should not be detected as container")
	}
	if ns != "" {
		t.Errorf("namespace for non-existent PID should be empty, got %q", ns)
	}

	// PID 1 (init) should be in the same namespace on a non-containerized host.
	// In a test container with its own PID namespace, PID 1 IS in a different
	// namespace from the test process, so we just verify no crash.
	ns1, _ := detectPIDNamespace(1)
	_ = ns1 // don't assert — depends on test environment
}

func TestSignDest(t *testing.T) {
	tests := []struct {
		name    string
		caller  *CallerContext
		session *SessionBindInfo
		want    string
	}{
		{
			name:   "ssh_dest present",
			caller: &CallerContext{SSHDest: "user@host"},
			want:   "user@host",
		},
		{
			name:    "session dest when no ssh_dest",
			caller:  &CallerContext{},
			session: &SessionBindInfo{DestHostname: "resolved.host"},
			want:    "resolved.host",
		},
		{
			name:   "unknown when neither",
			caller: &CallerContext{},
			want:   "unknown",
		},
		{
			name:    "ssh_dest takes precedence",
			caller:  &CallerContext{SSHDest: "user@host"},
			session: &SessionBindInfo{DestHostname: "other.host"},
			want:    "user@host",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SignDest(tt.caller, tt.session)
			if got != tt.want {
				t.Errorf("SignDest = %q, want %q", got, tt.want)
			}
		})
	}
}
