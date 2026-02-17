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
		// Combined flags: -p22 (value concatenated)
		{"ssh -p22 user@host", "user@host"},
		// Combined boolean + arg-taking flag: -NTfp 22
		{"ssh -NTfp 22 user@host", "user@host"},
		// Combined boolean flags only
		{"ssh -NTf user@host", "user@host"},
		// End of options marker
		{"ssh -- user@host", "user@host"},
		{"ssh -v -- user@host", "user@host"},
		{"ssh -p 22 -- user@host", "user@host"},
		// -- with no destination after it
		{"ssh --", ""},
		// Long option (not --)
		{"ssh --version", ""},
		// -l flag consumes next arg (login name), dest is the arg after
		{"ssh -l alice host", "host"},
		{"ssh -lalice host", "host"},
		// Concatenated -o value
		{"ssh -oStrictHostKeyChecking=no user@host", "user@host"},
		// IPv4/IPv6 boolean flags
		{"ssh -4 user@host", "user@host"},
		{"ssh -6 user@host", "user@host"},
		{"ssh -46 user@host", "user@host"},
		// Repeated boolean flag
		{"ssh -tt user@host", "user@host"},
		// -F with concatenated path
		{"ssh -F/dev/null user@host", "user@host"},
		// Multiple arg-consuming flags
		{"ssh -l alice -p 22 -i ~/.ssh/id host", "host"},
		// Boolean flags before -- with remote command containing dashes
		{"ssh -NT -- user@host -suspicious-looking-arg", "user@host"},
	}
	for _, tt := range tests {
		got := extractSSHDest(tt.cmdline)
		if got != tt.want {
			t.Errorf("extractSSHDest(%q) = %q, want %q", tt.cmdline, got, tt.want)
		}
	}
}


func TestExtractMuxVia(t *testing.T) {
	tests := []struct {
		name        string
		controlPath string // basename of ControlPath template
		cmdline     string
		want        string
	}{
		{
			name:        "%h_%p_%r standard",
			controlPath: "%h_%p_%r",
			cmdline:     "ssh: /home/alice/.ssh/sockets/nano_22_alice [mux]",
			want:        "alice@nano",
		},
		{
			name:        "%h_%p_%r dotted host",
			controlPath: "%h_%p_%r",
			cmdline:     "ssh: /tmp/sockets/host.example.com_22_user [mux]",
			want:        "user@host.example.com",
		},
		{
			name:        "%h_%p_%r host with underscore",
			controlPath: "%h_%p_%r",
			cmdline:     "ssh: /tmp/sockets/my_host_22_alice [mux]",
			want:        "alice@my_host",
		},
		{
			name:        "%r@%h:%p format",
			controlPath: "%r@%h:%p",
			cmdline:     "ssh: /home/alice/.ssh/sockets/alice@nano:22 [mux]",
			want:        "alice@nano",
		},
		{
			name:        "%r@%h:%p dotted host",
			controlPath: "%r@%h:%p",
			cmdline:     "ssh: /tmp/sockets/git@github.com:22 [mux]",
			want:        "git@github.com",
		},
		{
			name:        "%h-%p-%r format",
			controlPath: "%h-%p-%r",
			cmdline:     "ssh: /tmp/sockets/nano-22-alice [mux]",
			want:        "alice@nano",
		},
		{
			name:        "%h:%p no user",
			controlPath: "%h:%p",
			cmdline:     "ssh: /tmp/sockets/nano:22 [mux]",
			want:        "nano",
		},
		{
			name:        "not mux cmdline",
			controlPath: "%h_%p_%r",
			cmdline:     "ssh user@host",
			want:        "",
		},
		{
			name:        "empty cmdline",
			controlPath: "%h_%p_%r",
			cmdline:     "",
			want:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Compile the pattern from the ControlPath basename
			re := compileControlPathRegex(tt.controlPath)
			if re == nil {
				if tt.want != "" {
					t.Fatalf("compileControlPathRegex(%q) returned nil", tt.controlPath)
				}
				return
			}

			// Temporarily set the global regex
			saved := muxViaRegex.pattern
			muxViaRegex.pattern = re
			defer func() { muxViaRegex.pattern = saved }()

			got := extractMuxVia(tt.cmdline)
			if got != tt.want {
				t.Errorf("extractMuxVia(%q) = %q, want %q (regex: %s)", tt.cmdline, got, tt.want, re.String())
			}
		})
	}
}

func TestCompileControlPathRegex(t *testing.T) {
	// %C only — no host info extractable
	re := compileControlPathRegex("%C")
	if re != nil {
		t.Error("opaque hash ControlPath should return nil")
	}

	// ssh-%C — no %h, still nil
	re = compileControlPathRegex("ssh-%C")
	if re != nil {
		t.Error("hash ControlPath without host token should return nil")
	}

	// %h_%p_%r should compile
	re = compileControlPathRegex("%h_%p_%r")
	if re == nil {
		t.Fatal("h_p_r ControlPath should compile")
	}

	// Escaped literal percent
	re = compileControlPathRegex("ssh-%%-%h_%p")
	if re == nil {
		t.Fatal("should handle escaped percent")
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

func TestParseCgroup(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "cgroup v2",
			content: "0::/user.slice/user-1000.slice/session-1.scope\n",
			want:    "/user.slice/user-1000.slice/session-1.scope",
		},
		{
			name:    "cgroup v1 single controller",
			content: "12:blkio:/user.slice\n",
			want:    "12:blkio:/user.slice",
		},
		{
			name:    "cgroup v2 docker",
			content: "0::/system.slice/docker-abc123.scope\n",
			want:    "/system.slice/docker-abc123.scope",
		},
		{
			name:    "mixed v1 and v2",
			content: "1:name=systemd:/user.slice\n0::/user.slice/user-1000.slice\n",
			want:    "/user.slice/user-1000.slice",
		},
		{
			name:    "empty",
			content: "",
			want:    "",
		},
		{
			name:    "whitespace only",
			content: "  \n  \n",
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCgroup(tt.content)
			if got != tt.want {
				t.Errorf("parseCgroup(%q) = %q, want %q", tt.content, got, tt.want)
			}
		})
	}
}

func TestDetectNamespaces(t *testing.T) {
	// Our own PID should be in our own namespace (not a container)
	namespaces, mismatches, isContainer := detectNamespaces(int32(os.Getpid()))
	if isContainer {
		t.Error("own PID should not be detected as container")
	}
	if len(mismatches) > 0 {
		t.Errorf("own PID should have no mismatches, got %v", mismatches)
	}
	if len(namespaces) == 0 {
		t.Error("namespaces should not be empty for own PID")
	}
	// Should have read at least pid namespace
	if _, ok := namespaces["pid"]; !ok {
		t.Error("pid namespace should be present")
	}

	// Non-existent PID should return empty, not container
	namespaces, mismatches, isContainer = detectNamespaces(999999999)
	if isContainer {
		t.Error("non-existent PID should not be detected as container")
	}
	if len(mismatches) > 0 {
		t.Errorf("non-existent PID should have no mismatches, got %v", mismatches)
	}
	if len(namespaces) > 0 {
		t.Errorf("non-existent PID should have no namespaces, got %v", namespaces)
	}

	// PID 1 (init) — just verify no crash; results depend on test environment
	_, _, _ = detectNamespaces(1)
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
