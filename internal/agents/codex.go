package agents

import (
	"fmt"
	"strings"
)

type Codex struct{}

func (Codex) Name() string {
	return "codex"
}

func (Codex) Provider() string {
	return "openai"
}

func (Codex) DefaultConfigMode() string {
	return "ambient_ephemeral"
}

func (Codex) VersionPolicy() VersionPolicy {
	return VersionPolicy{Args: []string{"--version"}, MinimumVersion: "0.147.0", MaximumVersionExclusive: "0.148.0"}
}

func (Codex) BuildCommand(req RunRequest) (CommandSpec, error) {
	sandbox := req.CodexSandbox
	if sandbox != strings.TrimSpace(sandbox) {
		return CommandSpec{}, fmt.Errorf("Codex sandbox mode must not have surrounding whitespace")
	}
	switch sandbox {
	case "read-only", "workspace-write", "danger-full-access":
	default:
		return CommandSpec{}, fmt.Errorf("unsupported Codex sandbox mode %q; expected read-only, workspace-write, or danger-full-access", sandbox)
	}

	args := []string{
		"exec",
		"--json",
		"--ephemeral",
		"--sandbox",
		sandbox,
		"--cd",
		req.CWD,
	}
	for _, dir := range req.WritableDirs {
		args = append(args, "--add-dir", dir)
	}
	args = append(args, req.ExtraArgs...)
	if strings.TrimSpace(req.Model) != "" {
		args = append(args, "--model", strings.TrimSpace(req.Model))
	}
	args = append(args, "-")

	return CommandSpec{
		Path:           "codex",
		Args:           args,
		Dir:            req.CWD,
		Stdin:          req.Prompt,
		StdoutFilename: "codex-events.jsonl",
		StderrFilename: "codex.stderr.log",
	}, nil
}
