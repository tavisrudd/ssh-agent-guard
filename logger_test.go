package main

import (
	"testing"
)

func TestBuildSummary(t *testing.T) {
	tests := []struct {
		name    string
		caller  *CallerContext
		session *SessionBindInfo
		detail  string
		want    string
	}{
		{
			name:   "basic",
			caller: &CallerContext{Name: "ssh"},
			detail: "sign host",
			want:   "ssh: sign host",
		},
		{
			name:   "with tmux window",
			caller: &CallerContext{Name: "ssh", TmuxWindow: "main:dev"},
			detail: "sign host",
			want:   "[main:dev] ssh: sign host",
		},
		{
			name:   "with via host",
			caller: &CallerContext{Name: "ssh", ForwardedVia: "jump"},
			detail: "sign host",
			want:   "ssh: sign host via jump",
		},
		{
			name:   "claude prefix",
			caller: &CallerContext{Name: "ssh", IsClaude: true},
			detail: "sign host",
			want:   "claude:ssh: sign host",
		},
		{
			name:   "all decorations",
			caller: &CallerContext{Name: "ssh", IsClaude: true, TmuxWindow: "work:code", ForwardedVia: "bastion"},
			detail: "sign prod.example.com",
			want:   "claude:[work:code] ssh: sign prod.example.com via bastion",
		},
		{
			name:   "truncation at 60 chars",
			caller: &CallerContext{Name: "ssh", TmuxWindow: "very-long-session:very-long-window"},
			detail: "sign extremely-long-hostname.subdomain.example.com",
			// Full: "[very-long-session:very-long-window] ssh: sign extremely-long-hostname.subdomain.example.com"
			// Should be truncated to 60 chars
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildSummary(tt.caller, tt.session, tt.detail)
			if tt.want != "" && got != tt.want {
				t.Errorf("buildSummary = %q, want %q", got, tt.want)
			}
			if len(got) > 60 {
				t.Errorf("buildSummary length %d > 60: %q", len(got), got)
			}
		})
	}
}
