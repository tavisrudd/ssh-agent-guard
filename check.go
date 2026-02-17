package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type checkOutput struct {
	Context          checkContext          `yaml:"context"`
	PolicyEvaluation checkPolicyEvaluation `yaml:"policy_evaluation"`
	Result           checkResult           `yaml:"result"`
}

type checkContext struct {
	LocalPID                  int32             `yaml:"local_pid"`
	ProcessName               string            `yaml:"process_name"`
	ExePath                   string            `yaml:"exe_path,omitempty"`
	Cmdline                   string            `yaml:"cmdline"`
	LocalCWD                  string            `yaml:"local_cwd"`
	IsForwardedSession        bool              `yaml:"is_forwarded_session"`
	ForwardedSessionHeuristic string            `yaml:"forwarded_session_heuristic"`
	IsContainer               bool              `yaml:"is_container"`
	PIDNamespace              string            `yaml:"pid_namespace,omitempty"`
	IsClaude                  bool              `yaml:"is_claude"`
	TmuxWindow                string            `yaml:"tmux_window,omitempty"`
	SSHDest                   string            `yaml:"ssh_dest,omitempty"`
	ForwardedVia              string            `yaml:"forwarded_via,omitempty"`
	Env                       map[string]string `yaml:"env,omitempty"`
	LocalProcTree             []checkAncestor   `yaml:"local_proc_tree,omitempty"`
}

type checkAncestor struct {
	PID  int32  `yaml:"pid"`
	Name string `yaml:"name"`
	Cmd  string `yaml:"cmd"`
}

type checkPolicyEvaluation struct {
	PolicyFile string             `yaml:"policy_file"`
	Key        *string            `yaml:"key"` // nil → null
	Rules      []RuleCheckResult  `yaml:"rules"`
}

type checkResult struct {
	Action string `yaml:"action"`
	Rule   string `yaml:"rule"`
}

// runCheck gathers caller context and evaluates policy rules, printing results.
// Used for debugging/testing the proxy's view of processes and rule matching.
func runCheck(policyPath string, pid int, keyFingerprint string) {
	// Gather caller context
	var checkPID int32
	if pid > 0 {
		checkPID = int32(pid)
	} else {
		// Use parent PID (the shell running this command) for a more useful check
		checkPID = int32(os.Getppid())
	}

	ctx := getCallerContextFromPID(checkPID)

	// Build context section
	out := checkOutput{}
	out.Context = checkContext{
		LocalPID:                  ctx.PID,
		ProcessName:               ctx.Name,
		ExePath:                   ctx.ExePath,
		Cmdline:                   ctx.Cmdline,
		LocalCWD:                  ctx.CWD,
		IsForwardedSession:        ctx.IsForwardedSession,
		ForwardedSessionHeuristic: ctx.ForwardedSessionHeuristic,
		IsContainer:               ctx.IsContainer,
		PIDNamespace:              ctx.PIDNamespace,
		IsClaude:                  ctx.IsClaude,
		TmuxWindow:                ctx.TmuxWindow,
		SSHDest:                   ctx.SSHDest,
		ForwardedVia:              ctx.ForwardedVia,
		Env:                       ctx.Env,
	}
	for _, a := range ctx.Ancestry {
		out.Context.LocalProcTree = append(out.Context.LocalProcTree, checkAncestor{
			PID:  a.PID,
			Name: a.Name,
			Cmd:  a.Cmdline,
		})
	}

	// Build policy evaluation section
	out.PolicyEvaluation.PolicyFile = policyPath
	if keyFingerprint != "" {
		out.PolicyEvaluation.Key = &keyFingerprint
	}

	policy, _ := NewPolicy(policyPath)
	results := policy.EvaluateVerbose(ctx, nil, keyFingerprint)

	out.PolicyEvaluation.Rules = results

	// Build result section
	result := policy.Evaluate(ctx, nil, keyFingerprint)
	out.Result = checkResult{
		Action: result.Action.String(),
		Rule:   result.RuleName,
	}

	// Marshal and print
	data, err := yaml.Marshal(&out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "yaml marshal: %v\n", err)
		os.Exit(1)
	}
	os.Stdout.Write(data)
}
