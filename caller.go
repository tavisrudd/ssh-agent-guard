package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// muxViaRegex extracts host/user from ControlMaster socket paths.
// Compiled once from the user's ssh ControlPath setting via ssh -G.
// nil means ControlPath is unset, uses %C (opaque hash), or ssh -G failed.
var muxViaRegex struct {
	once    sync.Once
	pattern *regexp.Regexp
}

// initMuxViaRegex resolves the user's ControlPath and compiles a regex
// to extract host/user from mux master socket basenames. Call once at startup.
func initMuxViaRegex() {
	muxViaRegex.once.Do(func() {
		muxViaRegex.pattern = compileMuxViaRegex()
	})
}

func compileMuxViaRegex() *regexp.Regexp {
	sshBin := findBin("ssh")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, sshBin, "-G", "dummy")
	out, err := cmd.Output()
	if err != nil {
		log.Printf("mux-via: ssh -G failed: %v (forwarded_via unavailable for mux connections)", err)
		return nil
	}

	var controlPath string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "controlpath ") {
			controlPath = strings.TrimPrefix(line, "controlpath ")
			break
		}
	}

	if controlPath == "" || controlPath == "none" {
		return nil
	}

	base := filepath.Base(controlPath)
	re := compileControlPathRegex(base)
	if re != nil {
		log.Printf("mux-via: ControlPath %q → regex %s", controlPath, re.String())
	} else {
		log.Printf("mux-via: ControlPath %q not usable for forwarded_via extraction", controlPath)
	}
	return re
}

// compileControlPathRegex converts a ControlPath basename template into a
// regex with named capture groups for host, port, and user. Returns nil if
// the template has no %h/%n token (e.g. %C-only) or fails to compile.
func compileControlPathRegex(base string) *regexp.Regexp {
	// %C is an opaque SHA256 hash — can't extract host/user
	if !strings.Contains(base, "%h") && !strings.Contains(base, "%n") {
		return nil
	}

	// Convert SSH ControlPath tokens to regex capture groups.
	// %h/%n → hostname, %p → port, %r → remote user, %C → hex hash
	var pattern strings.Builder
	pattern.WriteString("^")
	for i := 0; i < len(base); i++ {
		if base[i] == '%' && i+1 < len(base) {
			switch base[i+1] {
			case 'h', 'n':
				pattern.WriteString(`(?P<host>.+?)`)
			case 'p':
				pattern.WriteString(`(?P<port>\d+)`)
			case 'r':
				pattern.WriteString(`(?P<user>.+?)`)
			case 'C':
				pattern.WriteString(`[a-f0-9]+`)
			case '%':
				pattern.WriteString(`%`)
			default:
				pattern.WriteString(`.+?`)
			}
			i++ // skip token character
		} else {
			pattern.WriteString(regexp.QuoteMeta(string(base[i])))
		}
	}
	pattern.WriteString("$")

	re, err := regexp.Compile(pattern.String())
	if err != nil {
		return nil
	}
	return re
}

// extractMuxVia extracts host/user from a ControlMaster mux cmdline.
// The mux master renames itself to "ssh: /path/to/socket [mux]", losing
// the original ssh destination. This function recovers it by parsing the
// socket basename using the regex compiled from the user's ControlPath.
// Returns "user@host", "host", or "".
func extractMuxVia(cmdline string) string {
	if muxViaRegex.pattern == nil {
		return ""
	}
	if !strings.HasPrefix(cmdline, "ssh: ") || !strings.HasSuffix(cmdline, " [mux]") {
		return ""
	}

	socketPath := strings.TrimPrefix(cmdline, "ssh: ")
	socketPath = strings.TrimSuffix(socketPath, " [mux]")
	base := filepath.Base(socketPath)

	match := muxViaRegex.pattern.FindStringSubmatch(base)
	if match == nil {
		return ""
	}

	var host, user string
	for i, name := range muxViaRegex.pattern.SubexpNames() {
		if i >= len(match) {
			break
		}
		switch name {
		case "host":
			host = match[i]
		case "user":
			user = match[i]
		}
	}

	if host == "" {
		return ""
	}
	if user != "" {
		return user + "@" + host
	}
	return host
}

// CallerContext holds information about the process that connected to the proxy.
// Gathered immediately on accept() via SO_PEERCRED + /proc, before the process
// can exit.
type CallerContext struct {
	PID        int32
	UID        uint32
	GID        uint32
	Name       string            // process name (nix-unwrapped)
	ExePath    string            // resolved executable path (/proc/$pid/exe)
	Cmdline    string            // full command line
	CWD        string            // working directory
	Cgroup     string            // cgroup path (/proc/$pid/cgroup)
	Env        map[string]string // selected environment variables
	TmuxWindow string            // resolved from TMUX_PANE
	Ancestry   []AncestorInfo    // process tree (self → init)
	SSHDest                   string // extracted from ssh cmdline
	ForwardedVia              string // intermediate host (user@host) from mux socket path
	IsCodingAgent             bool   // any coding agent heuristic matched
	CodingAgentName           string // which agent matched (e.g. "claude", "cursor")
	UserPresence          string // "local" or "remote", detected via UserPresenceHeuristic
	UserPresenceHeuristic string // how UserPresence was determined
	Namespaces          map[string]string // namespace inodes (key=ns name, value=inode)
	NamespaceMismatches []string          // namespaces that differ from proxy's own
	IsContainer         bool              // PID namespace differs (caller identity untrusted)
}

type AncestorInfo struct {
	PID     int32
	Name    string
	Cmdline string
}

// builtinEnvVars are always captured from /proc/$pid/environ regardless of config.
// Coding-agent-specific vars (e.g. CLAUDECODE) are pulled in automatically
// from the coding_agents heuristics — no need to list them here.
var builtinEnvVars = []string{
	"SSH_CONNECTION",
	"SSH_TTY",
	"DISPLAY",
	"WAYLAND_DISPLAY",
	"TERM",
	"TMUX_PANE",
	"XDG_SESSION_TYPE",
}

// getEnvVarsToCapture returns the active env var capture list.
// Uses the policy-computed list if available, otherwise falls back to builtins.
func getEnvVarsToCapture() []string {
	if v := envVarsCaptureListVal.Load(); v != nil {
		if list, ok := v.([]string); ok && len(list) > 0 {
			return list
		}
	}
	return builtinEnvVars
}

func getCallerContext(conn net.Conn) *CallerContext {
	ucred := getPeerCred(conn)
	if ucred == nil {
		return &CallerContext{Name: "unknown", Env: make(map[string]string)}
	}
	ctx := getCallerContextFromPID(ucred.Pid)
	ctx.UID = ucred.Uid
	ctx.GID = ucred.Gid
	return ctx
}

// getCallerContextFromPID gathers caller context from /proc for a given PID.
// Used by both the socket handler (via getCallerContext) and the check subcommand.
func getCallerContextFromPID(pid int32) *CallerContext {
	ctx := &CallerContext{
		PID: pid,
		Env: make(map[string]string),
	}

	procDir := fmt.Sprintf("/proc/%d", ctx.PID)

	// Command line (null-separated → space-separated)
	if data, err := os.ReadFile(filepath.Join(procDir, "cmdline")); err == nil {
		ctx.Cmdline = strings.TrimRight(strings.ReplaceAll(string(data), "\x00", " "), " ")
	}

	ctx.Name = processName(ctx.Cmdline)

	// Resolved executable path
	ctx.ExePath = readExePath(ctx.PID)

	// Working directory
	if target, err := os.Readlink(filepath.Join(procDir, "cwd")); err == nil {
		ctx.CWD = target
	}

	// Cgroup path
	if data, err := os.ReadFile(filepath.Join(procDir, "cgroup")); err == nil {
		ctx.Cgroup = parseCgroup(string(data))
	}

	// Selected environment variables
	readSelectedEnv(ctx, procDir)

	// Resolve tmux window name from TMUX_PANE
	if pane := ctx.Env["TMUX_PANE"]; pane != "" {
		ctx.TmuxWindow = resolveTmuxWindow(pane)
	}

	// Walk process ancestry (up to 8 levels)
	ctx.Ancestry = walkAncestry(ctx.PID, 8)

	// Detect coding agent (needs both env and ancestry)
	ctx.CodingAgentName, ctx.IsCodingAgent = detectCodingAgent(ctx)

	// Extract SSH destination from this process or its ancestors.
	// For forwarded sessions, this is the intermediate host (first hop);
	// proxy.go's Extension handler moves it to ForwardedVia when
	// session-bind confirms the session is forwarded.
	ctx.SSHDest = findSSHDest(ctx)

	// Detect user presence: local display or remote SSH session
	ctx.UserPresence = detectUserPresence(ctx)

	// Detect namespace mismatches (container/namespace isolation)
	ctx.Namespaces, ctx.NamespaceMismatches, ctx.IsContainer = detectNamespaces(ctx.PID)

	return ctx
}

// getPeerCred retrieves SO_PEERCRED from a Unix domain socket connection.
// Returns nil if the connection is not a UnixConn or the syscall fails.
func getPeerCred(conn net.Conn) *unix.Ucred {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return nil
	}

	var ucred *unix.Ucred
	var credErr error
	if err := rawConn.Control(func(fd uintptr) {
		ucred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		log.Printf("peercred: Control: %v", err)
		return nil
	}
	if credErr != nil {
		return nil
	}

	return ucred
}

// processName extracts a clean process name from a cmdline string.
// Strips nix wrapper prefixes/suffixes (.foo-wrapped → foo).
func processName(cmdline string) string {
	if cmdline == "" {
		return "unknown"
	}
	parts := strings.SplitN(cmdline, " ", 2)
	name := filepath.Base(parts[0])

	// Nix wrapping: strip leading "." and trailing "-wrapped"
	name = strings.TrimPrefix(name, ".")
	name = strings.TrimSuffix(name, "-wrapped")

	if name == "" {
		return "unknown"
	}
	return name
}

func readSelectedEnv(ctx *CallerContext, procDir string) {
	data, err := os.ReadFile(filepath.Join(procDir, "environ"))
	if err != nil {
		return
	}
	captureList := getEnvVarsToCapture()
	for _, entry := range strings.Split(string(data), "\x00") {
		for _, name := range captureList {
			if strings.HasPrefix(entry, name+"=") {
				ctx.Env[name] = strings.TrimPrefix(entry, name+"=")
			}
		}
	}
}

func resolveTmuxWindow(pane string) string {
	tmuxBin := findBin("tmux")
	out, err := exec.Command(tmuxBin, "display-message", "-t", pane, "-p",
		"#{session_name}:#{window_name}").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func walkAncestry(startPID int32, maxDepth int) []AncestorInfo {
	var ancestry []AncestorInfo
	pid := startPID
	for i := 0; i < maxDepth && pid > 1; i++ {
		info := AncestorInfo{PID: pid}

		procDir := fmt.Sprintf("/proc/%d", pid)
		if data, err := os.ReadFile(filepath.Join(procDir, "cmdline")); err == nil {
			info.Cmdline = strings.TrimRight(strings.ReplaceAll(string(data), "\x00", " "), " ")
		} else {
			// Process exited — stop walking
			break
		}

		info.Name = processName(info.Cmdline)
		ancestry = append(ancestry, info)

		ppid := getParentPID(pid)
		if ppid <= 1 {
			break
		}
		pid = int32(ppid)
	}
	return ancestry
}

func getParentPID(pid int32) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	s := string(data)

	// /proc/PID/stat format: pid (comm) state ppid ...
	// comm can contain spaces and parens, so find the LAST ")"
	closeParen := strings.LastIndex(s, ")")
	if closeParen < 0 || closeParen+2 >= len(s) {
		return 0
	}

	fields := strings.Fields(s[closeParen+2:])
	if len(fields) < 2 {
		return 0
	}

	ppid, err := strconv.Atoi(fields[1]) // field 0=state, 1=ppid
	if err != nil {
		return 0
	}
	return ppid
}

// detectUserPresence determines whether the human user is local or remote.
// For tmux callers, checks tmux's global environment (reflects current attach state).
// For non-tmux callers, checks /proc/pid/environ and process ancestry.
// Sets ctx.UserPresenceHeuristic to describe how the determination was made.
func detectUserPresence(ctx *CallerContext) string {
	// If in tmux, the tmux global environment is the source of truth —
	// it reflects whether the session is currently attached via SSH,
	// unlike /proc/pid/environ which is frozen at process birth.
	if ctx.Env["TMUX_PANE"] != "" {
		tmuxBin := findBin("tmux")
		out, err := exec.Command(tmuxBin, "show-environment", "SSH_CONNECTION").Output()
		if err == nil {
			line := strings.TrimSpace(string(out))
			if strings.HasPrefix(line, "SSH_CONNECTION=") {
				ctx.UserPresenceHeuristic = "tmux-env"
				return "remote"
			}
		}
		// tmux returned -SSH_CONNECTION (unset) or error — not remote
		ctx.UserPresenceHeuristic = "tmux-env"
		return "local"
	}

	// Not in tmux — fall back to /proc/pid/environ
	if ctx.Env["SSH_CONNECTION"] != "" {
		ctx.UserPresenceHeuristic = "proc-environ"
		return "remote"
	}
	for _, a := range ctx.Ancestry {
		if a.Name == "sshd" {
			ctx.UserPresenceHeuristic = "sshd-ancestry"
			return "remote"
		}
	}
	ctx.UserPresenceHeuristic = "none"
	return "local"
}

// findSSHDest extracts the SSH destination from the connecting process
// or its ancestors. The process connecting to the agent socket is typically
// the ssh client itself, whose cmdline contains the destination.
func findSSHDest(ctx *CallerContext) string {
	// Check self first, then ancestors
	if dest := extractSSHDest(ctx.Cmdline); dest != "" {
		return dest
	}
	for _, a := range ctx.Ancestry {
		if dest := extractSSHDest(a.Cmdline); dest != "" {
			return dest
		}
	}
	return ""
}

// selfNamespaces caches the proxy's own namespace inodes (they never change).
var selfNamespaces struct {
	once sync.Once
	ns   map[string]string
}

// nsNames are the Linux namespaces to compare for container detection.
var nsNames = []string{"pid", "mnt", "net", "user", "uts", "cgroup"}

func getSelfNamespaces() map[string]string {
	selfNamespaces.once.Do(func() {
		selfNamespaces.ns = make(map[string]string, len(nsNames))
		for _, name := range nsNames {
			if target, err := os.Readlink("/proc/self/ns/" + name); err == nil {
				selfNamespaces.ns[name] = target
			}
		}
	})
	return selfNamespaces.ns
}

// detectNamespaces reads all relevant namespaces for the peer process and
// compares them against the proxy's own. Returns the peer's namespace map,
// a list of mismatched namespace names, and whether the PID namespace differs.
//
// IsContainer is derived from PID namespace mismatch only. When the caller
// is in a different PID namespace, /proc reads may return empty or wrong data
// because the PID from SO_PEERCRED is translated across namespaces. Other
// namespace mismatches (mnt, net, user, uts, cgroup) don't affect /proc
// visibility and are captured in NamespaceMismatches for forensics only.
func detectNamespaces(pid int32) (namespaces map[string]string, mismatches []string, isContainer bool) {
	selfNS := getSelfNamespaces()
	if len(selfNS) == 0 {
		return nil, nil, false
	}

	// Check process existence first to distinguish "exited" from "ns unreadable"
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
		return nil, nil, false
	}

	peerNS := make(map[string]string, len(nsNames))
	pidMismatch := false
	for _, name := range nsNames {
		target, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", pid, name))
		if err != nil {
			continue
		}
		peerNS[name] = target
		if selfNS[name] != "" && selfNS[name] != target {
			mismatches = append(mismatches, name)
			if name == "pid" {
				pidMismatch = true
			}
		}
	}

	// If we couldn't read any ns files despite the process existing,
	// assume a namespace issue (conservative — treat as container)
	if len(peerNS) == 0 {
		return nil, []string{"unknown"}, true
	}

	return peerNS, mismatches, pidMismatch
}

// readExePath returns the resolved executable path via /proc/$pid/exe.
// Platform-specific: moves to caller_{linux,darwin}.go with the rest.
func readExePath(pid int32) string {
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return target
}

// bootTime caches the system boot time from /proc/stat (never changes).
var bootTime struct {
	once sync.Once
	time time.Time
}

func getBootTime() time.Time {
	bootTime.once.Do(func() {
		data, err := os.ReadFile("/proc/stat")
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "btime ") {
				sec, err := strconv.ParseInt(strings.TrimPrefix(line, "btime "), 10, 64)
				if err == nil {
					bootTime.time = time.Unix(sec, 0)
				}
				return
			}
		}
	})
	return bootTime.time
}

// readProcessAge returns how long the process has been running.
// Reads starttime (field 22) from /proc/$pid/stat and computes wall time.
// Platform-specific: moves to caller_{linux,darwin}.go with the rest.
func readProcessAge(pid int32) time.Duration {
	bt := getBootTime()
	if bt.IsZero() {
		return 0
	}

	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	s := string(data)

	// /proc/PID/stat format: pid (comm) state ppid ... starttime(field 22) ...
	// Fields after the closing paren (0-indexed): state=0 ppid=1 ... starttime=19
	closeParen := strings.LastIndex(s, ")")
	if closeParen < 0 || closeParen+2 >= len(s) {
		return 0
	}
	fields := strings.Fields(s[closeParen+2:])
	if len(fields) < 20 {
		return 0
	}

	startTicks, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil {
		return 0
	}

	// CLK_TCK is 100 on virtually all Linux systems
	const clockTicksPerSec = 100
	startTime := bt.Add(time.Duration(startTicks) * time.Second / clockTicksPerSec)
	age := time.Since(startTime)
	if age < 0 {
		return 0
	}
	return age
}

// parseCgroup extracts the cgroup path from /proc/$pid/cgroup content.
// On cgroup v2, returns the path after "0::". On v1, returns the full content trimmed.
func parseCgroup(content string) string {
	for _, line := range strings.Split(strings.TrimSpace(content), "\n") {
		if strings.HasPrefix(line, "0::") {
			return strings.TrimPrefix(line, "0::")
		}
	}
	// v1 or unexpected format — return first non-empty line
	for _, line := range strings.Split(strings.TrimSpace(content), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

// extractSSHDest parses an ssh command line for the destination argument.
// Returns "" if the cmdline is not an ssh command.
func extractSSHDest(cmdline string) string {
	args := strings.Fields(cmdline)
	if len(args) < 2 {
		return ""
	}

	// Check if this is an ssh command
	base := processName(args[0])
	if base != "ssh" {
		return ""
	}

	// SSH flags that consume the next argument (when separated by space)
	flagsWithArg := map[byte]bool{
		'b': true, 'c': true, 'D': true, 'E': true, 'e': true,
		'F': true, 'I': true, 'i': true, 'J': true, 'L': true,
		'l': true, 'm': true, 'O': true, 'o': true, 'p': true,
		'Q': true, 'R': true, 'S': true, 'W': true, 'w': true,
	}

	i := 1
	for i < len(args) {
		arg := args[i]
		if len(arg) > 1 && arg[0] == '-' && arg[1] != '-' {
			// Single-dash flag(s). Could be:
			//   -p 22          (flag with separate arg)
			//   -p22           (flag with concatenated arg)
			//   -NTf           (combined boolean flags)
			//   -NTfp 22       (combined booleans ending with arg-taking flag)
			// Walk the flag characters to determine behavior.
			consumed := false
			for j := 1; j < len(arg); j++ {
				if flagsWithArg[arg[j]] {
					if j+1 < len(arg) {
						// Value concatenated: -p22 — skip this arg
					} else {
						// Value is next arg: -p 22 — skip both
						i++
					}
					consumed = true
					break
				}
				// Boolean flag, continue to next char
			}
			_ = consumed
			i++
			continue
		}
		if arg == "--" {
			// End of options — next arg is the destination
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if strings.HasPrefix(arg, "--") {
			i++
			continue
		}
		// First non-flag argument is the destination
		return arg
	}
	return ""
}

// detectCodingAgent checks env vars and ancestry against the merged coding
// agent heuristics. Returns the agent name and true on first match.
// Agents are checked in sorted name order for deterministic results.
func detectCodingAgent(ctx *CallerContext) (string, bool) {
	h := getCodingAgentHeuristics()
	if h == nil {
		// No policy loaded yet — fall back to builtin CLAUDECODE check
		if ctx.Env["CLAUDECODE"] == "1" {
			return "claude", true
		}
		return "", false
	}

	// Build ancestor name set once for all agents
	ancestorNames := make(map[string]bool, len(ctx.Ancestry))
	for _, a := range ctx.Ancestry {
		ancestorNames[a.Name] = true
	}

	// Iterate in sorted order for deterministic results when
	// a caller matches heuristics for multiple agents.
	names := make([]string, 0, len(h.agents))
	for name := range h.agents {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		agent := h.agents[name]
		// Check env heuristics
		for envKey, envVal := range agent.Env {
			if ctx.Env[envKey] == envVal {
				return name, true
			}
		}
		// Check ancestor heuristics
		for _, ancestor := range agent.Ancestors {
			if ancestorNames[ancestor] {
				return name, true
			}
		}
	}
	return "", false
}

func getCodingAgentHeuristics() *codingAgentHeuristics {
	if v := codingAgentHeuristicsVal.Load(); v != nil {
		if h, ok := v.(*codingAgentHeuristics); ok {
			return h
		}
	}
	return nil
}
