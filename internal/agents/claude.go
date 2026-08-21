package agents

import (
	"fmt"
	"strings"
)

type Claude struct{}

func (Claude) Name() string {
	return "claude"
}

func (Claude) Provider() string {
	return "anthropic"
}

func (Claude) DefaultConfigMode() string {
	return "project_only_ephemeral"
}

func (Claude) VersionPolicy() VersionPolicy {
	return VersionPolicy{Args: []string{"--version"}, MinimumVersion: "2.1.235", MaximumVersionExclusive: "2.2.0"}
}

func (Claude) BuildCommand(req RunRequest) (CommandSpec, error) {
	if len(req.ExtraArgs) != 0 {
		return CommandSpec{}, fmt.Errorf("runtime bundle arguments are unsupported for Claude")
	}
	permissionMode := req.ClaudePermissionMode
	if permissionMode != strings.TrimSpace(permissionMode) {
		return CommandSpec{}, fmt.Errorf("Claude permission mode must not have surrounding whitespace")
	}
	switch permissionMode {
	case "acceptEdits", "auto", "bypassPermissions", "manual", "dontAsk", "plan":
	default:
		return CommandSpec{}, fmt.Errorf("unsupported Claude permission mode %q", permissionMode)
	}

	args := []string{
		"--print",
		"--output-format",
		"stream-json",
		"--verbose",
		"--no-session-persistence",
		"--setting-sources",
		"project",
		"--permission-mode",
		permissionMode,
	}
	for _, dir := range req.WritableDirs {
		args = append(args, "--add-dir", dir)
	}
	if strings.TrimSpace(req.Model) != "" {
		args = append(args, "--model", strings.TrimSpace(req.Model))
	}

	return CommandSpec{
		Path:           "claude",
		Args:           args,
		Dir:            req.CWD,
		Stdin:          req.Prompt,
		StdoutFilename: "claude-output.jsonl",
		StderrFilename: "claude.stderr.log",
	}, nil
}
