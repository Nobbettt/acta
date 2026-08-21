package gitdiff

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func run(t *testing.T, dir string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v: %s", name, args, err, out)
	}
	return string(out)
}

func readDiff(t *testing.T, dir, dest string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, dest))
	if err != nil {
		t.Fatalf("read %s: %v", dest, err)
	}
	return string(b)
}

// scrubGitConfig hides the developer's global/system git config so options
// like status.showUntrackedFiles=no or init.defaultObjectFormat can't change
// the behavior under test.
func scrubGitConfig(t *testing.T) {
	t.Helper()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
}

// isCommitSHA accepts both sha1 (40) and sha256 (64) object formats.
func isCommitSHA(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

func TestWorkspaceInfo(t *testing.T) {
	scrubGitConfig(t)
	dir := t.TempDir()
	run(t, dir, "git", "init", "-q")
	run(t, dir, "git", "checkout", "-qb", "main")

	// Unborn HEAD: no commits yet, but repo-ness and the branch are known.
	info, err := WorkspaceInfo(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsRepo || info.CommitSHA != "" || info.Branch != "main" || info.Dirty {
		t.Fatalf("unborn HEAD info = %+v, want clean repo on main without a commit", info)
	}

	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-qm", "init")
	// A tag with the branch's name must not turn Branch into "heads/main".
	run(t, dir, "git", "tag", "main")

	info, err = WorkspaceInfo(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !isCommitSHA(info.CommitSHA) || info.Branch != "main" || info.Dirty {
		t.Fatalf("info = %+v, want clean main with a commit SHA", info)
	}

	// Explicitly named generated dirs must not count as dirt, and untracked
	// dirt must be seen even under status.showUntrackedFiles=no.
	run(t, dir, "git", "config", "status.showUntrackedFiles", "no")
	if err := os.MkdirAll(filepath.Join(dir, ".acta", "runs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".acta", "runs", "run.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "out", "run-1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "out", "run-1", "run.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if info, err = WorkspaceInfo(context.Background(), dir, ".acta/runs", "out"); err != nil || info.Dirty {
		t.Fatalf("info = %+v, err = %v, want acta bundle dirs ignored by the dirty check", info, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("y\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if info, err = WorkspaceInfo(context.Background(), dir, ".acta/runs", "out"); err != nil || !info.Dirty {
		t.Fatalf("info = %+v, err = %v, want dirty workspace", info, err)
	}

	if info, err = WorkspaceInfo(context.Background(), t.TempDir()); err != nil || info != (Info{}) {
		t.Fatalf("non-git dir: info = %+v, err = %v, want zero info and nil error", info, err)
	}
}

// A failed status must surface as an error, never as a clean workspace.
func TestWorkspaceInfoSurfacesGitFailures(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := WorkspaceInfo(ctx, t.TempDir()); err == nil {
		t.Fatal("canceled git status must fail, not report a clean workspace")
	}
}

func TestWorkspaceFilesIgnoresInheritedRepositoryRedirects(t *testing.T) {
	scrubGitConfig(t)
	dir := t.TempDir()
	run(t, dir, "git", "init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "tracked.txt"), []byte("tracked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, dir, "git", "add", "tracked.txt")
	if err := os.WriteFile(filepath.Join(dir, "untracked.txt"), []byte("untracked\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	other := t.TempDir()
	run(t, other, "git", "init", "-q")
	t.Setenv("GIT_DIR", filepath.Join(other, ".git"))
	t.Setenv("GIT_WORK_TREE", other)
	t.Setenv("GIT_COMMON_DIR", filepath.Join(other, ".git"))
	t.Setenv("GIT_OBJECT_DIRECTORY", filepath.Join(other, ".git", "objects"))
	t.Setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", filepath.Join(other, ".git", "objects"))
	t.Setenv("GIT_INDEX_FILE", filepath.Join(other, ".git", "index"))

	files, err := WorkspaceFiles(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	joined := "\n" + strings.Join(files, "\n") + "\n"
	for _, name := range []string{"tracked.txt", "untracked.txt"} {
		if !strings.Contains(joined, "\n"+name+"\n") {
			t.Fatalf("workspace files = %v, want %s from the requested repository", files, name)
		}
	}
	info, err := WorkspaceInfo(context.Background(), dir)
	if err != nil || !info.IsRepo || !info.Dirty {
		t.Fatalf("redirected workspace info = %+v, err = %v", info, err)
	}
	dest := filepath.Join(dir, "redirect-proof.diff")
	if wrote, err := WorkspaceDiff(context.Background(), dir, dest, "redirect-proof.diff"); err != nil || !wrote {
		t.Fatalf("redirected workspace diff wrote=%v err=%v", wrote, err)
	}
	if diff, err := os.ReadFile(dest); err != nil || !strings.Contains(string(diff), "untracked.txt") {
		t.Fatalf("redirect-proof diff missing requested repository content: %v\n%s", err, diff)
	}
}

func TestHeadCommit(t *testing.T) {
	scrubGitConfig(t)
	dir := t.TempDir()

	// A non-git dir and an unborn HEAD are both "no head yet", not errors.
	if sha, err := HeadCommit(context.Background(), dir); err != nil || sha != "" {
		t.Fatalf("non-git head = %q, err = %v, want empty and nil", sha, err)
	}
	run(t, dir, "git", "init", "-q")
	if sha, err := HeadCommit(context.Background(), dir); err != nil || sha != "" {
		t.Fatalf("unborn head = %q, err = %v, want empty and nil", sha, err)
	}
	run(t, dir, "git", "commit", "-q", "--allow-empty", "-m", "init")
	if sha, err := HeadCommit(context.Background(), dir); err != nil || !isCommitSHA(sha) {
		t.Fatalf("head = %q, err = %v, want a commit SHA", sha, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := HeadCommit(ctx, dir); err == nil {
		t.Fatal("canceled head capture must fail, not report no commits")
	}
}

func TestWorkspaceDiff(t *testing.T) {
	dir := t.TempDir()
	run(t, dir, "git", "init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "tracked.txt"), []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-qm", "init")

	// Modify tracked, add untracked, and add generated directories that are
	// excluded only because the caller names their exact paths.
	if err := os.WriteFile(filepath.Join(dir, "tracked.txt"), []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "untracked.txt"), []byte("new file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".acta", "runs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".acta", "runs", "run.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".acta", "legitimate.txt"), []byte("evidence\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".stage-control", "stage-1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".stage-control", "stage-1", "stage-result.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	indexBefore, err := os.ReadFile(filepath.Join(dir, ".git", "index"))
	if err != nil {
		t.Fatal(err)
	}
	wrote, err := WorkspaceDiff(context.Background(), dir, filepath.Join(dir, "workspace.diff"), ".acta/runs", ".stage-control")
	if err != nil {
		t.Fatal(err)
	}
	if !wrote {
		t.Fatal("expected a diff to be written")
	}
	diff := readDiff(t, dir, "workspace.diff")
	if !strings.Contains(diff, "tracked.txt") || !strings.Contains(diff, "+changed") {
		t.Errorf("tracked change missing from diff:\n%s", diff)
	}
	if !strings.Contains(diff, "untracked.txt") || !strings.Contains(diff, "+new file") {
		t.Errorf("untracked file missing from diff:\n%s", diff)
	}
	if strings.Contains(diff, ".acta/runs") {
		t.Errorf("generated run directory must be excluded from diff:\n%s", diff)
	}
	if strings.Contains(diff, ".stage-control") {
		t.Errorf("the launcher's private stage-control directory must be excluded from diff:\n%s", diff)
	}
	if !strings.Contains(diff, ".acta/legitimate.txt") {
		t.Errorf("legitimate content adjacent to the generated run directory is missing:\n%s", diff)
	}

	// Index must be restored: untracked file back to untracked, nothing staged.
	status := run(t, dir, "git", "status", "--porcelain")
	if !strings.Contains(status, "?? untracked.txt") {
		t.Errorf("untracked file not restored after diff:\n%s", status)
	}
	if strings.Contains(status, "A  ") {
		t.Errorf("index not restored:\n%s", status)
	}
	indexAfter, err := os.ReadFile(filepath.Join(dir, ".git", "index"))
	if err != nil {
		t.Fatal(err)
	}
	if string(indexAfter) != string(indexBefore) {
		t.Fatal("workspace diff changed the caller's git index bytes")
	}
}

func TestWorkspaceDiffTreatsUntrackedNamesAsLiteralPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows filenames cannot contain a colon")
	}
	dir := t.TempDir()
	run(t, dir, "git", "init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "tracked.txt"), []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, dir, "git", "add", "tracked.txt")
	run(t, dir, "git", "commit", "-qm", "init")

	if err := os.WriteFile(filepath.Join(dir, "tracked.txt"), []byte("staged\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, dir, "git", "add", "tracked.txt")
	if err := os.WriteFile(filepath.Join(dir, ":(top)**"), []byte("magic filename\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, ".acta"), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := WorkspaceDiff(context.Background(), dir, filepath.Join(dir, ".acta", "workspace.diff")); err != nil {
		t.Fatal(err)
	}
	status := run(t, dir, "git", "status", "--porcelain")
	if !strings.Contains(status, "M  tracked.txt") {
		t.Fatalf("staged change was altered by workspace diff cleanup:\n%s", status)
	}
	if !strings.Contains(status, "?? :(top)**") {
		t.Fatalf("magic-looking filename was not restored as untracked:\n%s", status)
	}
}

func TestFilePatch(t *testing.T) {
	ctx := context.Background()
	patch, err := FilePatch(ctx, "src/clock.ts", FileVersion{
		Exists: true, Content: []byte("export const cycle = 'h12';\n"),
	}, FileVersion{
		Exists: true, Content: []byte("export const cycle = 'h23';\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"diff --git a/src/clock.ts b/src/clock.ts",
		"-export const cycle = 'h12';",
		"+export const cycle = 'h23';",
	} {
		if !strings.Contains(patch, want) {
			t.Fatalf("patch missing %q:\n%s", want, patch)
		}
	}

	added, err := FilePatch(ctx, "src/new.ts", FileVersion{}, FileVersion{Exists: true, Content: []byte("new line\n")})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(added, "new file mode 100644") || !strings.Contains(added, "--- /dev/null") || !strings.Contains(added, "+new line") {
		t.Fatalf("added file patch is incomplete:\n%s", added)
	}

	deleted, err := FilePatch(ctx, "src/old.ts", FileVersion{Exists: true, Content: []byte("old line\n")}, FileVersion{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(deleted, "deleted file mode 100644") || !strings.Contains(deleted, "+++ /dev/null") || !strings.Contains(deleted, "-old line") {
		t.Fatalf("deleted file patch is incomplete:\n%s", deleted)
	}

	executable, err := FilePatch(ctx, "bin/tool", FileVersion{}, FileVersion{
		Exists: true, Content: []byte("#!/bin/sh\n"), Mode: 0o755,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(executable, "new file mode 100755") {
		t.Fatalf("executable add has the wrong mode:\n%s", executable)
	}
	if strings.Contains(executable, "old mode ") {
		t.Fatalf("executable add contains contradictory mode-change metadata:\n%s", executable)
	}

	modeOnly, err := FilePatch(ctx, "bin/tool", FileVersion{
		Exists: true, Content: []byte("#!/bin/sh\n"), Mode: 0o644,
	}, FileVersion{
		Exists: true, Content: []byte("#!/bin/sh\n"), Mode: 0o755,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(modeOnly, "old mode 100644") || !strings.Contains(modeOnly, "new mode 100755") {
		t.Fatalf("mode-only patch is incomplete:\n%s", modeOnly)
	}
}

// A run bundle stored outside .acta (custom --runs-dir) must be excluded so a
// run never captures its own raw stream/metadata into workspace.diff.
func TestWorkspaceDiffExcludesRunsDir(t *testing.T) {
	dir := t.TempDir()
	run(t, dir, "git", "init", "-q")
	run(t, dir, "git", "commit", "-q", "--allow-empty", "-m", "init")

	// A real untracked change plus a bundle under a custom runs dir "out".
	if err := os.WriteFile(filepath.Join(dir, "real.txt"), []byte("work\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(dir, "out", "run-1")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "codex-events.jsonl"), []byte("{\"big\":\"stream\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(bundle, "workspace.diff")
	wrote, err := WorkspaceDiff(context.Background(), dir, dest, "out")
	if err != nil {
		t.Fatal(err)
	}
	if !wrote {
		t.Fatal("expected real.txt change to be written")
	}
	diff := readDiff(t, dir, filepath.Join("out", "run-1", "workspace.diff"))
	if !strings.Contains(diff, "real.txt") {
		t.Errorf("real change missing:\n%s", diff)
	}
	if strings.Contains(diff, "codex-events.jsonl") || strings.Contains(diff, "out/run-1") {
		t.Errorf("run bundle must be excluded from its own diff:\n%s", diff)
	}
}

// An empty diff must leave no file behind, so digest's presence check stays honest.
func TestWorkspaceDiffEmptyNoFile(t *testing.T) {
	dir := t.TempDir()
	run(t, dir, "git", "init", "-q")
	run(t, dir, "git", "commit", "-q", "--allow-empty", "-m", "init")

	dest := filepath.Join(dir, "workspace.diff")
	wrote, err := WorkspaceDiff(context.Background(), dir, dest)
	if err != nil {
		t.Fatal(err)
	}
	if wrote {
		t.Fatal("clean workspace should write no diff")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("empty diff must leave no file, stat err = %v", err)
	}
}

func TestWorkspaceDiffLimitLeavesNoPartialArtifact(t *testing.T) {
	dir := t.TempDir()
	run(t, dir, "git", "init", "-q")
	run(t, dir, "git", "commit", "-q", "--allow-empty", "-m", "init")
	if err := os.WriteFile(filepath.Join(dir, "large.txt"), []byte(strings.Repeat("content\n", 128)), 0o644); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "workspace.diff")
	wrote, err := WorkspaceDiffWithLimit(context.Background(), dir, dest, 64)
	if err == nil || wrote || !strings.Contains(err.Error(), "64-byte limit") {
		t.Fatalf("limited diff wrote=%v err=%v", wrote, err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("limited diff left a partial artifact: %v", err)
	}
}

func TestWorkspaceDiffNotARepo(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "workspace.diff")
	wrote, err := WorkspaceDiff(context.Background(), dir, dest)
	if err != nil || wrote {
		t.Errorf("non-repo should be a no-op, got wrote=%v err=%v", wrote, err)
	}
}

func TestWorkspaceDiffSurfacesGitDetectionErrors(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wrote, err := WorkspaceDiff(ctx, dir, filepath.Join(dir, "workspace.diff"))
	if err == nil || wrote {
		t.Fatalf("canceled git detection should fail, got wrote=%v err=%v", wrote, err)
	}
}
