package agents

import (
	"strings"
	"testing"
)

func TestGetAndNames(t *testing.T) {
	if _, err := Get("nope"); err == nil {
		t.Error("unknown agent should error")
	}
	if (Codex{}).Name() != "codex" {
		t.Errorf("Codex.Name() = %q, want codex", (Codex{}).Name())
	}
	if (Claude{}).Name() != "claude" {
		t.Errorf("Claude.Name() = %q, want claude", (Claude{}).Name())
	}
}

// Every resolvable agent must declare a GenAI provider, so tracing derives it
// from the adapter rather than a separate name-keyed switch that can drift.
func TestAdaptersDeclareProvider(t *testing.T) {
	want := map[string]string{"codex": "openai", "claude": "anthropic", "claude-code": "anthropic"}
	for name, provider := range want {
		a, err := Get(name)
		if err != nil {
			t.Fatalf("Get(%q): %v", name, err)
		}
		if got := a.Provider(); got != provider {
			t.Errorf("Get(%q).Provider() = %q, want %q", name, got, provider)
		}
	}
}

func TestAdaptersDeclareDefaultConfigMode(t *testing.T) {
	if got := (Codex{}).DefaultConfigMode(); got != "ambient_ephemeral" {
		t.Fatalf("Codex config mode = %q", got)
	}
	if got := (Claude{}).DefaultConfigMode(); got != "project_only_ephemeral" {
		t.Fatalf("Claude config mode = %q", got)
	}
}

func TestAdapterVersionPolicies(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		want    string
		wantErr bool
		minimum string
		maximum string
	}{
		{name: "codex current", output: "codex-cli 0.147.0", want: "0.147.0", minimum: "0.147.0", maximum: "0.148.0"},
		{name: "claude supported patch", output: "2.1.999 (Claude Code)", want: "2.1.999", minimum: "2.1.235", maximum: "2.2.0"},
		{name: "future range", output: "2.2.0 (Claude Code)", want: "2.2.0", wantErr: true, minimum: "2.1.235", maximum: "2.2.0"},
		{name: "older", output: "codex-cli 0.146.9", want: "0.146.9", wantErr: true, minimum: "0.147.0"},
		{name: "prerelease", output: "codex-cli 0.147.0-alpha.1", wantErr: true, minimum: "0.147.0"},
		{name: "build metadata", output: "codex-cli 0.147.0+build.1", want: "0.147.0", minimum: "0.147.0"},
		{name: "malformed", output: "development build", wantErr: true, minimum: "0.147.0"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := VersionPolicy{Args: []string{"--version"}, MinimumVersion: test.minimum, MaximumVersionExclusive: test.maximum}
			got, err := policy.ParseAndValidate(test.output)
			if got != test.want || (err != nil) != test.wantErr {
				t.Fatalf("ParseAndValidate() = %q, %v; want %q, error=%v", got, err, test.want, test.wantErr)
			}
		})
	}

	if got := (Codex{}).VersionPolicy().MinimumVersion; got != "0.147.0" {
		t.Fatalf("Codex minimum = %q", got)
	}
	if got := (Claude{}).VersionPolicy().MinimumVersion; got != "2.1.235" {
		t.Fatalf("Claude minimum = %q", got)
	}
	if got := (Codex{}).VersionPolicy().MaximumVersionExclusive; got != "0.148.0" {
		t.Fatalf("Codex maximum-exclusive = %q", got)
	}
	if got := (Claude{}).VersionPolicy().MaximumVersionExclusive; got != "2.2.0" {
		t.Fatalf("Claude maximum-exclusive = %q", got)
	}
}

func TestAdaptersRejectImplicitOrInvalidModes(t *testing.T) {
	for _, mode := range []string{"", " ", "workspace-write ", "unknown"} {
		if _, err := (Codex{}).BuildCommand(RunRequest{CWD: "/repo", CodexSandbox: mode}); err == nil {
			t.Errorf("Codex.BuildCommand sandbox %q unexpectedly succeeded", mode)
		}
	}
	for _, mode := range []string{"", " ", "acceptEdits ", "unknown"} {
		if _, err := (Claude{}).BuildCommand(RunRequest{CWD: "/repo", ClaudePermissionMode: mode}); err == nil {
			t.Errorf("Claude.BuildCommand permission mode %q unexpectedly succeeded", mode)
		}
	}
}

func TestCodexBuildCommand(t *testing.T) {
	spec, err := (Codex{}).BuildCommand(RunRequest{
		CWD:          "/repo",
		Prompt:       "fix it",
		Model:        "gpt-test",
		WritableDirs: []string{"/control"},
		CodexSandbox: "workspace-write",
	})
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"exec",
		"--json",
		"--ephemeral",
		"--sandbox",
		"workspace-write",
		"--cd",
		"/repo",
		"--add-dir",
		"/control",
		"--model",
		"gpt-test",
		"-",
	}
	assertStringSlice(t, spec.Args, want)
	if spec.Stdin != "fix it" {
		t.Fatalf("stdin = %q, want prompt", spec.Stdin)
	}
	if spec.Dir != "/repo" {
		t.Fatalf("dir = %q, want /repo", spec.Dir)
	}
	if spec.StdoutFilename != "codex-events.jsonl" {
		t.Fatalf("stdout filename = %q", spec.StdoutFilename)
	}
}

func TestClaudeBuildCommandKeepsPromptOutOfArgv(t *testing.T) {
	spec, err := (Claude{}).BuildCommand(RunRequest{
		CWD:                  "/repo",
		Prompt:               "secret task",
		WritableDirs:         []string{"/control"},
		ClaudePermissionMode: "acceptEdits",
	})
	if err != nil {
		t.Fatal(err)
	}

	if spec.Stdin != "secret task" {
		t.Fatalf("stdin = %q, want prompt", spec.Stdin)
	}
	for _, arg := range spec.CommandForRecord() {
		if strings.Contains(arg, "secret") {
			t.Fatalf("prompt leaked into argv: %q", arg)
		}
	}
	if !strings.Contains(strings.Join(spec.Args, "\x00"), "--add-dir\x00/control") {
		t.Fatalf("args = %#v, want explicit writable directory", spec.Args)
	}
	if !strings.Contains(strings.Join(spec.Args, "\x00"), "--setting-sources\x00project") {
		t.Fatalf("args = %#v, want project-only settings inheritance", spec.Args)
	}
	if !strings.Contains(strings.Join(spec.Args, "\x00"), "--no-session-persistence") {
		t.Fatalf("args = %#v, want session persistence disabled", spec.Args)
	}
}

func assertStringSlice(t *testing.T, got []string, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d; got %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("item %d = %q, want %q; got %#v", i, got[i], want[i], got)
		}
	}
}
