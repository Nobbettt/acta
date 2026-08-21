package doctor

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCheckCommandFailsWhenVersionFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell command requires /bin/sh")
	}
	bin := t.TempDir()
	path := filepath.Join(bin, "codex")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho broken >&2\nexit 7\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	check := checkCommand("codex")
	if check.OK {
		t.Fatalf("version failure reported OK: %+v", check)
	}
}

func TestRunWithOptionsChecksOnlySelectedAgentAndGit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell commands require /bin/sh")
	}
	bin := t.TempDir()
	for _, name := range []string{"git", "codex"} {
		path := filepath.Join(bin, name)
		version := "git version 2.45.0"
		if name == "codex" {
			version = "codex-cli 0.147.0"
		}
		script := "#!/bin/sh\n"
		if name == "codex" {
			script += "if [ \"$1\" = \"--version\" ]; then echo '" + version + "'; else echo '--ephemeral --ignore-user-config --ignore-rules --strict-config --sandbox --add-dir'; fi\n"
		} else {
			script += "echo '" + version + "'\n"
		}
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
	cwd := t.TempDir()
	checks := RunWithOptions(Options{CWD: cwd, RunsDir: "generated/runs", Agent: "codex"})
	joined := ""
	for _, check := range checks {
		joined += " " + check.Name
		if !check.OK {
			t.Fatalf("check failed: %+v", check)
		}
	}
	if !strings.Contains(joined, " git") || !strings.Contains(joined, " codex") || strings.Contains(joined, " claude") {
		t.Fatalf("selected-agent checks = %q", joined)
	}
	if _, err := os.Stat(filepath.Join(cwd, "generated")); !os.IsNotExist(err) {
		t.Fatalf("doctor permanently created the runs hierarchy: %v", err)
	}
}

func TestCheckAgentRejectsMissingRequiredFlag(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell command requires /bin/sh")
	}
	bin := t.TempDir()
	path := filepath.Join(bin, "codex")
	script := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'codex-cli 0.147.0'; else echo '--ephemeral'; fi\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	check := checkAgent("codex")
	if check.OK || !strings.Contains(check.Message, "lacks required flag") {
		t.Fatalf("missing flag check = %+v", check)
	}
}

func TestCheckRunsDirRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires additional privileges")
	}
	cwd := t.TempDir()
	target := t.TempDir()
	link := filepath.Join(cwd, "runs-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	check := checkRunsDir(cwd, link)
	if check.OK {
		t.Fatalf("symlinked runs dir accepted: %+v", check)
	}
}

func TestRunWithOptionsRejectsMissingCWDWithoutCreatingIt(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing", "workspace")
	checks := RunWithOptions(Options{CWD: missing, Agent: "codex"})
	if checks[0].Name != "cwd" || checks[0].OK {
		t.Fatalf("cwd check = %+v, want failure", checks[0])
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("doctor created missing cwd: %v", err)
	}
}

func TestRunWithOptionsRejectsUnknownAgent(t *testing.T) {
	checks := RunWithOptions(Options{CWD: t.TempDir(), Agent: "other"})
	found := false
	for _, check := range checks {
		if check.Name == "agent" {
			found = true
			if check.OK {
				t.Fatalf("unknown agent check reported OK: %+v", check)
			}
		}
	}
	if !found {
		t.Fatal("unknown agent did not produce an agent check")
	}
}

func TestCheckAgentRejectsUnsupportedVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell command requires /bin/sh")
	}
	bin := t.TempDir()
	path := filepath.Join(bin, "codex")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho 'codex-cli 0.146.9'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	check := checkAgent("codex")
	if check.OK || !strings.Contains(check.Message, "minimum supported version 0.147.0") {
		t.Fatalf("unsupported version check = %+v", check)
	}
}
