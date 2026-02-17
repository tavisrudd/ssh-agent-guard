package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// logEvent is the unified YAML structure for sign/mutation log files
// and the pending/previous sections of current.yaml.
type logEvent struct {
	Timestamp                 string            `yaml:"timestamp"`
	Trigger                   string            `yaml:"trigger"`
	ProcessName               string            `yaml:"process_name"`
	LocalPID                  int32             `yaml:"local_pid"`
	UID                       uint32            `yaml:"uid,omitempty"`
	GID                       uint32            `yaml:"gid,omitempty"`
	ExePath                   string            `yaml:"exe_path,omitempty"`
	TmuxWindow                string            `yaml:"tmux_window,omitempty"`
	KeyFingerprint            string            `yaml:"key_fingerprint,omitempty"`
	SSHDest                   string            `yaml:"ssh_dest,omitempty"`
	ForwardedVia              string            `yaml:"forwarded_via,omitempty"`
	IsForwarded               *bool             `yaml:"is_forwarded,omitempty"`
	DestKeyFingerprint        string            `yaml:"dest_key_fingerprint,omitempty"`
	LocalCWD                  string            `yaml:"local_cwd"`
	IsForwardedSession        bool              `yaml:"is_forwarded_session"`
	ForwardedSessionHeuristic string            `yaml:"forwarded_session_heuristic"`
	IsContainer               bool              `yaml:"is_container,omitempty"`
	PIDNamespace              string            `yaml:"pid_namespace,omitempty"`
	IsCodingAgent             bool              `yaml:"is_coding_agent,omitempty"`
	CodingAgentName           string            `yaml:"coding_agent_name,omitempty"`
	Decision                  string            `yaml:"decision"`
	Rule                      string            `yaml:"rule,omitempty"`
	ConfirmMethod             string            `yaml:"confirm_method,omitempty"`
	LogFile                   string            `yaml:"log_file,omitempty"`
	ConfigSHA256              string            `yaml:"config_sha256,omitempty"`
	Env                       map[string]string `yaml:"env,omitempty"`
	LocalProcTree             []logAncestor     `yaml:"local_proc_tree,omitempty"`
	Forensics                 *DenyForensics    `yaml:"forensics,omitempty"`
}

type logAncestor struct {
	PID     int32  `yaml:"pid"`
	Name    string `yaml:"name"`
	Command string `yaml:"command"`
}

// currentStatus is the YAML structure for current.yaml.
type currentStatus struct {
	State    string        `yaml:"state"`
	Text     string        `yaml:"text,omitempty"`
	Config   *ConfigStatus `yaml:"config,omitempty"`
	Pending  *logEvent     `yaml:"pending,omitempty"`
	Previous *logEvent     `yaml:"previous,omitempty"`
}

// literalString marshals as a YAML block scalar (| style) for human readability.
type literalString string

func (s literalString) MarshalYAML() (interface{}, error) {
	return &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: string(s),
		Style: yaml.LiteralStyle,
	}, nil
}

// configReloadLog is the YAML structure for successful config reload log files.
// Includes full config content so log entries can be tied back to specific
// configs even after those config files are gone.
type configReloadLog struct {
	Timestamp     string        `yaml:"timestamp"`
	Trigger       string        `yaml:"trigger"`
	ConfigSHA256  string        `yaml:"config_sha256"`
	ConfigContent literalString `yaml:"config_content"`
}

// configReloadFailedLog is the YAML structure for failed config reload log files.
type configReloadFailedLog struct {
	Timestamp       string          `yaml:"timestamp"`
	Trigger         string          `yaml:"trigger"`
	Errors          []string        `yaml:"errors"`
	ActiveConfigSHA string          `yaml:"active_config_sha256,omitempty"`
	BadConfig       *badConfigEntry `yaml:"bad_config,omitempty"`
}

// badConfigEntry holds the content and SHA256 of a config file that failed to parse.
type badConfigEntry struct {
	SHA256  string        `yaml:"sha256"`
	Content literalString `yaml:"content"`
}

// Logger writes event detail files (YAML) and maintains current.yaml
// via an external render helper, following the same patterns as gpg-log-caller.
type Logger struct {
	stateDir        string
	renderBin       string
	mu              sync.Mutex
	previous        *logEvent // stored for current.yaml previous section
	policy          *Policy   // for config status in current.yaml
	lastLoggedSHA   string    // SHA256 of last config snapshot written (skip duplicates)
}

func NewLogger(stateDir string, policy *Policy) *Logger {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		log.Printf("mkdir %s: %v", stateDir, err)
	}
	return &Logger{
		stateDir:  stateDir,
		renderBin: findBin("ssh-ag-render-status"),
		policy:    policy,
	}
}

// SignDest returns the best destination string for a sign event.
func SignDest(ctx *CallerContext, session *SessionBindInfo) string {
	dest := ctx.SSHDest
	if dest == "" && session != nil && session.DestHostname != "" {
		dest = session.DestHostname
	}
	if dest == "" {
		dest = "unknown"
	}
	return dest
}

// buildSignEvent creates a logEvent for a sign operation.
func buildSignEvent(ts time.Time, ctx *CallerContext, key ssh.PublicKey, session *SessionBindInfo, result *EvalResult, logPath string, forensics *DenyForensics) *logEvent {
	fingerprint := ssh.FingerprintSHA256(key)
	dest := SignDest(ctx, session)

	decision := result.Action.String()
	if result.Confirmed != nil {
		if *result.Confirmed {
			decision = "confirmed"
		} else {
			decision = "confirm-denied"
		}
	}

	ev := &logEvent{
		Timestamp:                 ts.Format("2006-01-02T15:04:05"),
		Trigger:                   "sign",
		ProcessName:               ctx.Name,
		LocalPID:                  ctx.PID,
		UID:                       ctx.UID,
		GID:                       ctx.GID,
		ExePath:                   ctx.ExePath,
		TmuxWindow:                ctx.TmuxWindow,
		KeyFingerprint:            fingerprint,
		SSHDest:                   dest,
		ForwardedVia:              ctx.ForwardedVia,
		LocalCWD:                  ctx.CWD,
		IsForwardedSession:        ctx.IsForwardedSession,
		ForwardedSessionHeuristic: ctx.ForwardedSessionHeuristic,
		IsContainer:               ctx.IsContainer,
		PIDNamespace:              ctx.PIDNamespace,
		IsCodingAgent:             ctx.IsCodingAgent,
		CodingAgentName:           ctx.CodingAgentName,
		Decision:                  decision,
		Rule:                      result.RuleName,
		ConfirmMethod:             result.ConfirmMethod,
		LogFile:                   logPath,
		Env:                       ctx.Env,
		Forensics:                 forensics,
	}

	if session != nil {
		ev.IsForwarded = &session.IsForwarded
		ev.DestKeyFingerprint = session.DestKeyFingerprint
	}

	for _, a := range ctx.Ancestry {
		ev.LocalProcTree = append(ev.LocalProcTree, logAncestor{
			PID:     a.PID,
			Name:    a.Name,
			Command: a.Cmdline,
		})
	}

	return ev
}

// buildMutationEvent creates a logEvent for a blocked mutation operation.
func buildMutationEvent(ts time.Time, ctx *CallerContext, op string, logPath string, forensics *DenyForensics) *logEvent {
	ev := &logEvent{
		Timestamp:                 ts.Format("2006-01-02T15:04:05"),
		Trigger:                   op,
		ProcessName:               ctx.Name,
		LocalPID:                  ctx.PID,
		UID:                       ctx.UID,
		GID:                       ctx.GID,
		ExePath:                   ctx.ExePath,
		LocalCWD:                  ctx.CWD,
		IsForwardedSession:        ctx.IsForwardedSession,
		ForwardedSessionHeuristic: ctx.ForwardedSessionHeuristic,
		IsContainer:               ctx.IsContainer,
		PIDNamespace:              ctx.PIDNamespace,
		IsCodingAgent:             ctx.IsCodingAgent,
		CodingAgentName:           ctx.CodingAgentName,
		Decision:                  "deny",
		LogFile:                   logPath,
		Forensics:                 forensics,
	}

	for _, a := range ctx.Ancestry {
		ev.LocalProcTree = append(ev.LocalProcTree, logAncestor{
			PID:     a.PID,
			Name:    a.Name,
			Command: a.Cmdline,
		})
	}

	return ev
}

// UpdateSignStatus logs a sign event to the journal.
// Status bar updates are handled by LogSign (final result) and SetConfirming.
func (l *Logger) UpdateSignStatus(ctx *CallerContext, key ssh.PublicKey, session *SessionBindInfo, result EvalResult) {
	fingerprint := ssh.FingerprintSHA256(key)
	dest := SignDest(ctx, session)

	via := ""
	if ctx.ForwardedVia != "" {
		via = fmt.Sprintf(" (via %s)", ctx.ForwardedVia)
	}
	container := ""
	if ctx.IsContainer {
		container = " container=true"
	}
	log.Printf("sign: %s → %s%s [%s/%s] (key %s) pid=%d%s",
		ctx.Name, dest, via, result.Action, result.RuleName, fingerprint[:19], ctx.PID, container)
}

// SetConfirming updates current.yaml to show a pending confirmation.
// Called from evalAndConfirm before the actual confirmation method runs.
func (l *Logger) SetConfirming(ctx *CallerContext, key ssh.PublicKey, session *SessionBindInfo, result EvalResult) {
	dest := SignDest(ctx, session)
	summary := buildSummary(ctx, session, fmt.Sprintf("sign %s", dest))

	var text string
	switch result.ConfirmMethod {
	case "touch":
		text = fmt.Sprintf("TOUCH YK: %s", summary)
	default:
		text = fmt.Sprintf("CONFIRM: %s", summary)
	}

	now := time.Now()
	pending := buildSignEvent(now, ctx, key, session, &result, "", nil)

	l.mu.Lock()
	defer l.mu.Unlock()

	status := currentStatus{
		State:    "confirming",
		Text:     text,
		Pending:  pending,
		Previous: l.previous,
	}

	l.writeCurrentAndRender(&status)
}

// LogSign writes the YAML log file and updates current.yaml with full details.
// forensics is optional — non-nil only for denied requests.
func (l *Logger) LogSign(ctx *CallerContext, key ssh.PublicKey, session *SessionBindInfo, result EvalResult, forensics *DenyForensics) {
	now := time.Now()
	fingerprint := ssh.FingerprintSHA256(key)
	dest := SignDest(ctx, session)

	// Determine decision string for filename
	decision := result.Action.String()
	if result.Confirmed != nil {
		if *result.Confirmed {
			decision = "confirmed"
		} else {
			decision = "confirm-denied"
		}
	}

	slug := ctx.Name
	if ctx.TmuxWindow != "" {
		slug += "." + ctx.TmuxWindow
	}
	filename := fmt.Sprintf("%s-%s-%s-%s.yaml", now.Format("20060102-150405"), slug, dest, decision)
	logPath := filepath.Join(l.stateDir, filename)

	// Build event and write log file.
	// NOTE: ConfigSHA256 is read here at log-write time, not at evaluation time.
	// If a config reload occurs during a long confirmation wait (e.g. YubiKey touch),
	// the sha may be one version newer than the policy that evaluated the request.
	ev := buildSignEvent(now, ctx, key, session, &result, "", forensics)
	if l.policy != nil {
		ev.ConfigSHA256 = l.policy.ConfigSHA256()
	}
	writeLogFile(logPath, ev)

	// Journal line for final result
	via := ""
	if ctx.ForwardedVia != "" {
		via = fmt.Sprintf(" (via %s)", ctx.ForwardedVia)
	}
	method := ""
	if result.ConfirmMethod != "" {
		method = fmt.Sprintf(" method=%s", result.ConfirmMethod)
	}
	log.Printf("sign: %s → %s%s [%s/%s]%s (key %s) pid=%d",
		ctx.Name, dest, via, decision, result.RuleName, method, fingerprint[:19], ctx.PID)

	// Store previous with log_file path for current.yaml
	ev.LogFile = logPath

	l.mu.Lock()
	defer l.mu.Unlock()

	l.previous = ev
	summary := buildSummary(ctx, session, fmt.Sprintf("sign %s", dest))
	l.writeIdle(summary)
}

// LogMutation logs a blocked key management operation.
// forensics is optional — provides additional context for the deny.
func (l *Logger) LogMutation(ctx *CallerContext, op string, forensics *DenyForensics) {
	now := time.Now()

	filename := fmt.Sprintf("%s-%s.yaml", now.Format("20060102-150405"), ctx.Name)
	logPath := filepath.Join(l.stateDir, filename)

	// Build event and write log file
	ev := buildMutationEvent(now, ctx, op, "", forensics)
	if l.policy != nil {
		ev.ConfigSHA256 = l.policy.ConfigSHA256()
	}
	writeLogFile(logPath, ev)

	log.Printf("DENIED %s from %s pid=%d", op, ctx.Name, ctx.PID)

	// Store previous with log_file path for current.yaml
	ev.LogFile = logPath

	l.mu.Lock()
	defer l.mu.Unlock()

	l.previous = ev
	summary := buildSummary(ctx, nil, fmt.Sprintf("%s DENIED", op))
	l.writeIdle(summary)
}

// NotifyReload updates current.yaml to show that the config was reloaded
// and renders the status bar. Called from SIGHUP and fsnotify reload paths.
func (l *Logger) NotifyReload() {
	l.mu.Lock()
	defer l.mu.Unlock()

	status := currentStatus{
		State:    "reloaded",
		Text:     "config reloaded",
		Previous: l.previous,
	}

	l.writeCurrentAndRender(&status)
}

// LogConfigChange writes a timestamped config log file to the state directory.
// On success (result.OK), writes a config-reload file with the active config's
// SHA256 and full content — but only if the SHA256 actually changed.
// On failure (!result.OK), always writes a config-reload-failed file with
// errors and the bad file content from the LoadResult.
func (l *Logger) LogConfigChange(result LoadResult) {
	now := time.Now()
	ts := now.Format("2006-01-02T15:04:05")

	if !result.OK {
		filename := fmt.Sprintf("%s-config-reload-failed.yaml", now.Format("20060102-150405"))
		logPath := filepath.Join(l.stateDir, filename)

		var activeSHA string
		if l.policy != nil {
			activeSHA = l.policy.ConfigSHA256()
		}
		ev := &configReloadFailedLog{
			Timestamp:       ts,
			Trigger:         "config-reload-failed",
			Errors:          result.Errors,
			ActiveConfigSHA: activeSHA,
		}
		if result.BadConfigSHA != "" {
			ev.BadConfig = &badConfigEntry{
				SHA256:  result.BadConfigSHA,
				Content: literalString(result.BadContent),
			}
		}

		data, err := yaml.Marshal(ev)
		if err != nil {
			log.Printf("yaml marshal config reload failed: %v", err)
			return
		}
		if err := os.WriteFile(logPath, data, 0600); err != nil {
			log.Printf("log write %s: %v", logPath, err)
		}
		return
	}

	// Success — only write if config actually changed.
	// The sha dedup also handles the Watch + SIGHUP race: both paths serialize
	// through Policy.Load()'s mutex, and the second caller here sees the sha
	// was already logged and skips the duplicate write.
	if l.policy == nil {
		return
	}
	sha := l.policy.ConfigSHA256()
	if sha == "" {
		return // no config file loaded (file absent)
	}

	// lastLoggedSHA is set before the file write. If WriteFile fails, the next
	// reload with the same sha will be skipped — acceptable since a write failure
	// implies a persistent disk issue affecting all logging.
	l.mu.Lock()
	if sha == l.lastLoggedSHA {
		l.mu.Unlock()
		return
	}
	l.lastLoggedSHA = sha
	l.mu.Unlock()

	filename := fmt.Sprintf("%s-config-reload.yaml", now.Format("20060102-150405"))
	logPath := filepath.Join(l.stateDir, filename)

	ev := &configReloadLog{
		Timestamp:     ts,
		Trigger:       "config-reload",
		ConfigSHA256:  sha,
		ConfigContent: literalString(l.policy.ConfigContent()),
	}

	data, err := yaml.Marshal(ev)
	if err != nil {
		log.Printf("yaml marshal config reload: %v", err)
		return
	}
	if err := os.WriteFile(logPath, data, 0600); err != nil {
		log.Printf("log write %s: %v", logPath, err)
	}
}

// writeIdle writes current.yaml with state=idle + stored previous. Must hold l.mu.
// text is the display summary for the render script's linger period.
// Render runs async — the sign response is not blocked by status bar updates.
func (l *Logger) writeIdle(text string) {
	status := currentStatus{
		State:    "idle",
		Text:     text,
		Previous: l.previous,
	}
	l.writeCurrentFile(&status)
	go l.render()
}

// writeCurrentAndRender writes current.yaml and renders synchronously.
// Used for SetConfirming where the UI must update before the confirmation prompt.
// Must hold l.mu.
func (l *Logger) writeCurrentAndRender(status *currentStatus) {
	l.writeCurrentFile(status)
	l.render()
}

// writeCurrentFile marshals a currentStatus to current.yaml. Must hold l.mu.
// Automatically includes config version/health from the policy.
func (l *Logger) writeCurrentFile(status *currentStatus) {
	if l.policy != nil {
		cs := l.policy.ConfigStatus()
		status.Config = &cs
	}
	data, err := yaml.Marshal(status)
	if err != nil {
		log.Printf("yaml marshal current: %v", err)
		return
	}
	currentFile := filepath.Join(l.stateDir, "current.yaml")
	if err := os.WriteFile(currentFile, data, 0600); err != nil {
		log.Printf("write %s: %v", currentFile, err)
	}
}

// render calls the external render helper to produce i3status + tmux-status.
func (l *Logger) render() {
	cmd := exec.Command(l.renderBin)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Printf("render-status: %v", err)
	}
}

// writeLogFile marshals a logEvent to a YAML file.
func writeLogFile(path string, ev *logEvent) {
	data, err := yaml.Marshal(ev)
	if err != nil {
		log.Printf("yaml marshal log: %v", err)
		return
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		log.Printf("log write %s: %v", path, err)
	}
}

func buildSummary(ctx *CallerContext, session *SessionBindInfo, detail string) string {
	prefix := ""
	if ctx.CodingAgentName != "" {
		prefix = ctx.CodingAgentName + ":"
	}
	if ctx.TmuxWindow != "" {
		prefix += fmt.Sprintf("[%s] ", ctx.TmuxWindow)
	}
	suffix := ""
	if ctx.ForwardedVia != "" {
		suffix = fmt.Sprintf(" via %s", ctx.ForwardedVia)
	}
	summary := fmt.Sprintf("%s%s: %s%s", prefix, ctx.Name, detail, suffix)
	if len(summary) > 60 {
		summary = summary[:60]
	}
	return summary
}
