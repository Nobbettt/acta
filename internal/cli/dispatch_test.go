package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func execCode(t *testing.T, args ...string) int {
	t.Helper()
	var stdout, stderr bytes.Buffer
	return Execute(context.Background(), args, strings.NewReader(""), &stdout, &stderr)
}

func TestExecuteDispatch(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"help", []string{"help"}, 0},
		{"no args", nil, 2},
		{"unknown command", []string{"bogus"}, 2},
		{"run without agent", []string{"run"}, 2},
		{"run without prompt", []string{"run", "--agent", "codex"}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := execCode(t, c.args...); got != c.want {
				t.Fatalf("Execute(%v) = %d, want %d", c.args, got, c.want)
			}
		})
	}
}

func TestExecuteDoctor(t *testing.T) {
	// doctor runs filesystem checks; it reports OK/FAIL but must not be an
	// argument error (2) for valid flags.
	code := execCode(t, "doctor", "--agent", "codex", "--cwd", t.TempDir(), "--runs-dir", t.TempDir())
	if code != 0 && code != 1 {
		t.Fatalf("doctor exit = %d, want 0 or 1", code)
	}
}

// An unknown agent fails in runner.Run before any subprocess is spawned.
func TestExecuteRunUnknownAgent(t *testing.T) {
	code := execCode(t, "run", "--agent", "bogus", "--prompt", "hi",
		"--cwd", t.TempDir(), "--runs-dir", t.TempDir())
	if code != 1 {
		t.Fatalf("unknown agent should exit 1, got %d", code)
	}
}
