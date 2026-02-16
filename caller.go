package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// CallerContext holds information about the process that connected to the proxy.
// Gathered immediately on accept() via SO_PEERCRED + /proc, before the process
// can exit.
type CallerContext struct {
	PID        int32
	UID        uint32
	GID        uint32
	Name       string            // process name (nix-unwrapped)
	Cmdline    string            // full command line
	CWD        string            // working directory
	Env        map[string]string // selected environment variables
	TmuxWindow string            // resolved from TMUX_PANE
	Ancestry   []AncestorInfo    // process tree (self → init)
	SSHDest                   string // extracted from ssh cmdline
	ForwardedVia              string // intermediate host (user@host) from mux socket path
	IsClaude                  bool   // CLAUDECODE=1 in env
	IsForwardedSession        bool   // detected via ForwardedSessionHeuristic
	ForwardedSessionHeuristic string // how IsForwardedSession was determined
	IsContainer       bool   // caller is in a different PID namespace
	PIDNamespace      string // PID namespace inode (e.g. "pid:[4026531836]")
}

type AncestorInfo struct {
	PID     int32
	Name    string
	Cmdline string
}

// envVarsToCapture are read from /proc/$pid/environ for logging context.
var envVarsToCapture = []string{
	"SSH_CONNECTION",
	"SSH_TTY",
	"DISPLAY",
	"WAYLAND_DISPLAY",
	"TERM",
	"TMUX_PANE",
	"CLAUDECODE",
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
// Used by both the socket handler (via getCallerContext) and --check mode.
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

	// Working directory
	if target, err := os.Readlink(filepath.Join(procDir, "cwd")); err == nil {
		ctx.CWD = target
	}

	// Selected environment variables
	readSelectedEnv(ctx, procDir)

	// Resolve tmux window name from TMUX_PANE
	if pane := ctx.Env["TMUX_PANE"]; pane != "" {
		ctx.TmuxWindow = resolveTmuxWindow(pane)
	}

	ctx.IsClaude = ctx.Env["CLAUDECODE"] == "1"

	// Walk process ancestry (up to 8 levels)
	ctx.Ancestry = walkAncestry(ctx.PID, 8)

	// Extract SSH destination from this process or its ancestors
	ctx.SSHDest = findSSHDest(ctx)

	// For mux processes, extract the intermediate host from socket path
	ctx.ForwardedVia = parseMuxViaHost(ctx.Cmdline)

	// Detect forwarded session: sshd in ancestry or SSH_CONNECTION in env
	ctx.IsForwardedSession = detectForwardedSession(ctx)

	// Detect PID namespace mismatch (container/namespace isolation)
	ctx.PIDNamespace, ctx.IsContainer = detectPIDNamespace(ctx.PID)

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
	for _, entry := range strings.Split(string(data), "\x00") {
		for _, name := range envVarsToCapture {
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

// detectForwardedSession checks if the caller is running inside a forwarded SSH session.
// For tmux callers, checks tmux's global environment (reflects current attach state).
// For non-tmux callers, checks /proc/pid/environ and process ancestry.
// Sets ctx.ForwardedSessionHeuristic to describe how the determination was made.
func detectForwardedSession(ctx *CallerContext) bool {
	// If in tmux, the tmux global environment is the source of truth —
	// it reflects whether the session is currently attached via SSH,
	// unlike /proc/pid/environ which is frozen at process birth.
	if ctx.Env["TMUX_PANE"] != "" {
		tmuxBin := findBin("tmux")
		out, err := exec.Command(tmuxBin, "show-environment", "SSH_CONNECTION").Output()
		if err == nil {
			line := strings.TrimSpace(string(out))
			if strings.HasPrefix(line, "SSH_CONNECTION=") {
				ctx.ForwardedSessionHeuristic = "tmux-env"
				return true
			}
		}
		// tmux returned -SSH_CONNECTION (unset) or error — not remote
		ctx.ForwardedSessionHeuristic = "tmux-env"
		return false
	}

	// Not in tmux — fall back to /proc/pid/environ
	if ctx.Env["SSH_CONNECTION"] != "" {
		ctx.ForwardedSessionHeuristic = "proc-environ"
		return true
	}
	for _, a := range ctx.Ancestry {
		if a.Name == "sshd" {
			ctx.ForwardedSessionHeuristic = "sshd-ancestry"
			return true
		}
	}
	ctx.ForwardedSessionHeuristic = "none"
	return false
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

// parseMuxViaHost extracts the intermediate host from an SSH mux process cmdline.
// Pattern: "ssh: /path/to/sockets/host_port_user [mux]"
// ControlPath is typically %h_%p_%r, so the socket name is host_port_user.
func parseMuxViaHost(cmdline string) string {
	if !strings.HasPrefix(cmdline, "ssh: ") || !strings.HasSuffix(cmdline, " [mux]") {
		return ""
	}
	socketPath := strings.TrimPrefix(cmdline, "ssh: ")
	socketPath = strings.TrimSuffix(socketPath, " [mux]")

	base := filepath.Base(socketPath)
	// ControlPath %h_%p_%r → host_port_user
	parts := strings.SplitN(base, "_", 3)
	if len(parts) >= 3 && parts[0] != "" && parts[2] != "" {
		return parts[2] + "@" + parts[0] // user@host
	}
	if len(parts) >= 1 && parts[0] != "" {
		return parts[0]
	}
	return ""
}

// detectPIDNamespace checks if the caller is in a different PID namespace.
// Returns the caller's PID namespace identifier and whether it differs from ours.
//
// When a container process connects via a bind-mounted SSH_AUTH_SOCK, SO_PEERCRED
// returns the PID translated to the receiver's namespace (correct on Linux 3.x+),
// but /proc reads may return empty or wrong data if the namespaces differ in ways
// that affect /proc visibility. The namespace check lets policy rules distinguish
// container callers and apply stricter defaults.
func detectPIDNamespace(pid int32) (namespace string, isContainer bool) {
	selfNS, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		return "", false
	}
	peerNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
	if err != nil {
		// Can't read peer namespace — might be permissions or process exited.
		// If /proc/$pid exists but ns/pid is unreadable, likely a namespace issue.
		if _, statErr := os.Stat(fmt.Sprintf("/proc/%d", pid)); statErr == nil {
			return "unknown", true
		}
		return "", false
	}
	return peerNS, selfNS != peerNS
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
