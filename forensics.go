package main

import (
	"fmt"
	"time"
)

// DenyForensics holds additional context collected only for denied requests.
// Attached to logEvent.Forensics when a sign or mutation request is denied.
type DenyForensics struct {
	SignRequestNum int                `yaml:"sign_request_num,omitempty"`
	ProcessAge     string             `yaml:"process_age,omitempty"`
	RuleTrace      []RuleCheckResult  `yaml:"rule_trace,omitempty"`
}

// collectDenyForensics gathers forensic context for a denied sign request.
// Called only on deny paths — the cost of EvaluateVerbose and readProcessAge
// is not incurred for allowed requests.
func collectDenyForensics(
	caller *CallerContext,
	session *SessionBindInfo,
	keyFingerprint string,
	policy *Policy,
	signRequestNum int,
) *DenyForensics {
	f := &DenyForensics{
		SignRequestNum: signRequestNum,
	}

	// Process age (platform-specific)
	if age := readProcessAge(caller.PID); age > 0 {
		f.ProcessAge = formatAge(age)
	}

	// Rule evaluation trace (platform-neutral)
	if policy != nil {
		f.RuleTrace = policy.EvaluateVerbose(caller, session, keyFingerprint)
	}

	return f
}

// collectMutationForensics gathers forensic context for a denied mutation.
// Mutations bypass policy evaluation, so there is no rule trace.
func collectMutationForensics(caller *CallerContext) *DenyForensics {
	f := &DenyForensics{}

	if age := readProcessAge(caller.PID); age > 0 {
		f.ProcessAge = formatAge(age)
	}

	return f
}

// formatAge formats a duration as a human-readable age string.
// Uses the coarsest unit that's >= 1: "3s", "2m15s", "1h30m", "2d3h".
func formatAge(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		if s == 0 {
			return fmt.Sprintf("%dm", m)
		}
		return fmt.Sprintf("%dm%ds", m, s)
	}
	if d < 24*time.Hour {
		h := int(d.Hours())
		m := int(d.Minutes()) % 60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh%dm", h, m)
	}
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	if h == 0 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dd%dh", days, h)
}
