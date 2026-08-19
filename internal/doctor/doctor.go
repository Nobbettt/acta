package doctor

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nobbettt/acta/internal/agents"
)

const maxVersionOutputBytes = 64 << 10

type Check struct {
	Name    string
	OK      bool
	Message string
}

type Options struct {
	CWD     string
	RunsDir string
	// Agent restricts checks to one selected adapter (codex or claude). Empty
	// retains the broad diagnostic that checks both installed adapters.
	Agent string
}

func Run(cwd string, runsDir string) []Check {
	return RunWithOptions(Options{CWD: cwd, RunsDir: runsDir})
}

func RunWithOptions(opts Options) []Check {
	checks := []Check{checkCWD(opts.CWD), checkCommand("git")}
	switch agent := strings.ToLower(strings.TrimSpace(opts.Agent)); agent {
	case "":
		checks = append(checks, checkAgent("codex"), checkAgent("claude"))
	case "codex", "claude":
		checks = append(checks, checkAgent(agent))
	default:
		checks = append(checks, Check{Name: "agent", OK: false, Message: fmt.Sprintf("unknown agent %q; expected codex or claude", opts.Agent)})
	}
	checks = append(checks, checkRunsDir(opts.CWD, opts.RunsDir))
	return checks
}

func checkAgent(name string) Check {
	adapter, err := agents.Get(name)
	if err != nil {
		return Check{Name: name, OK: false, Message: err.Error()}
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return Check{Name: name, OK: false, Message: "not found on PATH"}
	}
	policy := adapter.VersionPolicy()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, policy.Args...)
	out, overflow, err := boundedCommandOutput(cmd)
	if overflow {
		return Check{Name: name, OK: false, Message: fmt.Sprintf("found at %s; version output exceeds %d-byte limit", path, maxVersionOutputBytes)}
	}
	if err != nil {
		message := strings.TrimSpace(out)
		if message == "" {
			message = err.Error()
		}
		return Check{Name: name, OK: false, Message: fmt.Sprintf("found at %s; version check failed: %s", path, message)}
	}
	version, err := policy.ParseAndValidate(out)
	if err != nil {
		return Check{Name: name, OK: false, Message: fmt.Sprintf("found at %s; incompatible: %v", path, err)}
	}
	helpArgs, requiredFlags := agentHelpContract(name)
	helpCtx, helpCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer helpCancel()
	helpCommand := exec.CommandContext(helpCtx, path, helpArgs...)
	help, helpOverflow, helpErr := boundedCommandOutput(helpCommand)
	if helpErr != nil || helpOverflow {
		return Check{Name: name, OK: false, Message: fmt.Sprintf("found at %s; required-flag help check failed", path)}
	}
	for _, required := range requiredFlags {
		if !strings.Contains(help, required) {
			return Check{Name: name, OK: false, Message: fmt.Sprintf("found at %s; version %s lacks required flag %s", path, version, required)}
		}
	}
	versionRange := ">=" + policy.MinimumVersion
	if policy.MaximumVersionExclusive != "" {
		versionRange += ", <" + policy.MaximumVersionExclusive
	}
	return Check{Name: name, OK: true, Message: fmt.Sprintf("%s (%s; supported %s; required flags verified)", path, version, versionRange)}
}

func agentHelpContract(name string) ([]string, []string) {
	if name == "codex" {
		return []string{"exec", "--help"}, []string{"--ephemeral", "--ignore-user-config", "--ignore-rules", "--strict-config", "--sandbox", "--add-dir"}
	}
	return []string{"--help"}, []string{"--no-session-persistence", "--setting-sources", "--permission-mode", "--add-dir"}
}

func checkCWD(cwd string) Check {
	if strings.TrimSpace(cwd) == "" {
		cwd = "."
	}
	abs, err := filepath.Abs(cwd)
	if err != nil {
		return Check{Name: "cwd", OK: false, Message: err.Error()}
	}
	info, err := os.Stat(abs)
	if err != nil {
		return Check{Name: "cwd", OK: false, Message: err.Error()}
	}
	if !info.IsDir() {
		return Check{Name: "cwd", OK: false, Message: "not a directory: " + abs}
	}
	return Check{Name: "cwd", OK: true, Message: abs}
}

func checkCommand(name string) Check {
	path, err := exec.LookPath(name)
	if err != nil {
		return Check{Name: name, OK: false, Message: "not found on PATH"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, "--version")
	out, overflow, err := boundedCommandOutput(cmd)
	if overflow {
		return Check{Name: name, OK: false, Message: fmt.Sprintf("found at %s; version output exceeds %d-byte limit", path, maxVersionOutputBytes)}
	}
	version := strings.TrimSpace(out)
	if err != nil {
		if version == "" {
			version = err.Error()
		}
		return Check{Name: name, OK: false, Message: fmt.Sprintf("found at %s; version check failed: %s", path, version)}
	}
	if version == "" {
		version = "version output empty"
	}
	return Check{Name: name, OK: true, Message: fmt.Sprintf("%s (%s)", path, version)}
}

type boundedOutput struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	overflow bool
}

func (w *boundedOutput) Write(payload []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	remaining := maxVersionOutputBytes - w.buffer.Len()
	if remaining > 0 {
		keep := len(payload)
		if keep > remaining {
			keep = remaining
		}
		_, _ = w.buffer.Write(payload[:keep])
	}
	if len(payload) > remaining {
		w.overflow = true
	}
	return len(payload), nil
}

func boundedCommandOutput(cmd *exec.Cmd) (string, bool, error) {
	capture := &boundedOutput{}
	cmd.Stdout = capture
	cmd.Stderr = capture
	err := cmd.Run()
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.buffer.String(), capture.overflow, err
}

func checkRunsDir(cwd string, runsDir string) Check {
	if strings.TrimSpace(cwd) == "" {
		cwd = "."
	}
	absCWD, err := filepath.Abs(cwd)
	if err != nil {
		return Check{Name: "runs-dir", OK: false, Message: err.Error()}
	}
	target := strings.TrimSpace(runsDir)
	if target == "" {
		target = ".acta/runs"
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(absCWD, target)
	}
	target = filepath.Clean(target)
	probeParent := target
	if info, statErr := os.Lstat(target); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return Check{Name: "runs-dir", OK: false, Message: "not a directory: " + target}
		}
	} else if !os.IsNotExist(statErr) {
		return Check{Name: "runs-dir", OK: false, Message: statErr.Error()}
	} else {
		for {
			probeParent = filepath.Dir(probeParent)
			info, parentErr := os.Stat(probeParent)
			if parentErr == nil {
				if !info.IsDir() {
					return Check{Name: "runs-dir", OK: false, Message: "parent is not a directory: " + probeParent}
				}
				break
			}
			if !os.IsNotExist(parentErr) || filepath.Dir(probeParent) == probeParent {
				return Check{Name: "runs-dir", OK: false, Message: parentErr.Error()}
			}
		}
	}
	// Probe with a temporary directory (the runner creates a 0700 directory),
	// and remove it before returning. This validates writability without leaving
	// a missing --cwd or runs hierarchy behind.
	temp, err := os.MkdirTemp(probeParent, ".acta-doctor-")
	if err != nil {
		return Check{Name: "runs-dir", OK: false, Message: err.Error()}
	}
	if err := os.Chmod(temp, 0o700); err != nil {
		_ = os.Remove(temp)
		return Check{Name: "runs-dir", OK: false, Message: err.Error()}
	}
	if removeErr := os.Remove(temp); removeErr != nil {
		return Check{Name: "runs-dir", OK: false, Message: removeErr.Error()}
	}
	return Check{Name: "runs-dir", OK: true, Message: target}
}
