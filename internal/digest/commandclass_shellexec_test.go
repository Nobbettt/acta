// Covers the shapes where the shell itself decides what runs: eval and other
// code loaders that can change the working directory, literal backticks, and
// carriage return as an ordinary word character rather than whitespace.
package digest

import (
	"reflect"
	"slices"
	"testing"
)

func TestClassifyCommandRejectsUnmodelledShellExecution(t *testing.T) {
	cases := []struct {
		name    string
		command string
		exitOK  bool
	}{
		{"errexit skips network command", "set -e; false; curl https://example.com", false},
		{"long errexit form skips vcs read", "set -o errexit; false; git status", false},
		{"backtick substitution cannot borrow outer success", "echo `false && rm victim && true`", true},
		{"adjacent trailing semicolons are invalid", "curl https://never.example/path;;", false},
		{"leading semicolon is invalid", "; curl https://never.example/path", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if facts := classifyCommand(c.command, "", c.exitOK, testWorkspace()); facts != nil {
				t.Errorf("classifyCommand(%q) = %+v, want nil", c.command, facts)
			}
		})
	}
}

func TestClassifyCommandKeepsLiteralBackticks(t *testing.T) {
	commands := []string{
		"git status '`'",
		"git status \\`",
	}
	for _, command := range commands {
		facts := classifyCommand(command, "", false, testWorkspace())
		if facts == nil || !slices.Contains(facts.categories, "vcs.read") {
			t.Errorf("classifyCommand(%q) = %+v, want vcs.read", command, facts)
		}
	}
}

func TestClassifyCommandWithholdsCommandsAfterParentShellCodeLoaders(t *testing.T) {
	commands := []string{
		"eval 'cd /tmp' && rm victim.txt",
		"source setup.sh && rm victim.txt",
		". setup.sh && rm victim.txt",
		"eval 'exit 0' && npm install lodash",
		"</dev/null eval 'cd /tmp' && rm victim.txt",
		"time </dev/null eval 'exit 0' && npm install lodash",
	}
	for _, command := range commands {
		if facts := classifyCommand(command, "", true, testWorkspace()); facts != nil {
			t.Errorf("classifyCommand(%q) = %+v, want nil after unmodelled parent-shell code", command, facts)
		}
	}
}

func TestShellCarriageReturnIsPartOfAWord(t *testing.T) {
	cases := []struct {
		command string
		want    []string
	}{
		{"env\r", []string{"env\r"}},
		{"rm safe\rvictim", []string{"rm", "safe\rvictim"}},
		{"git rev-parse HEAD\r#not-comment", []string{"git", "rev-parse", "HEAD\r#not-comment"}},
	}
	for _, c := range cases {
		if got := shellTokens(c.command); !reflect.DeepEqual(got, c.want) {
			t.Errorf("shellTokens(%q) = %#v, want %#v", c.command, got, c.want)
		}
	}
}

func TestClassifyCommandPreservesCarriageReturns(t *testing.T) {
	cases := []struct {
		name        string
		command     string
		output      string
		exitOK      bool
		wantTargets []CommandTarget
		wantChanges []ShellMutation
	}{
		{"failed env with carriage return is a different command", "env\r", "", false, nil, nil},
		{"carriage return does not start a comment", "git rev-parse HEAD\r#not-comment", testHeadSHA + "\n", false, nil, nil},
		{
			"carriage return stays inside one deletion path",
			"rm safe\rvictim",
			"",
			true,
			[]CommandTarget{{Kind: "path", Value: "safe\rvictim"}},
			[]ShellMutation{{Kind: "delete", Path: "safe\rvictim"}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			facts := classifyCommand(c.command, c.output, c.exitOK, testWorkspace())
			if c.wantTargets == nil && c.wantChanges == nil {
				if facts != nil {
					t.Errorf("classifyCommand(%q) = %+v, want nil", c.command, facts)
				}
				return
			}
			if facts == nil {
				t.Fatalf("classifyCommand(%q) = nil", c.command)
			}
			if !reflect.DeepEqual(facts.targets, c.wantTargets) {
				t.Errorf("targets = %+v, want %+v", facts.targets, c.wantTargets)
			}
			if !reflect.DeepEqual(facts.mutations, c.wantChanges) {
				t.Errorf("mutations = %+v, want %+v", facts.mutations, c.wantChanges)
			}
		})
	}
}
