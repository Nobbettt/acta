// Package gitdiff captures the full workspace diff after an agent run:
// staged + unstaged changes plus non-ignored untracked files. Ignored files are
// outside this evidence contract unless they are already tracked.
package gitdiff

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/nobbettt/acta/internal/securefile"
)

const (
	maxBufferedGitOutputBytes int64 = 64 << 20
	maxGitDiagnosticBytes     int64 = 1 << 20
)

var ErrWorkspaceDiffLimit = errors.New("workspace diff byte limit exceeded")

// FileVersion is one side of a captured file edit. Exists distinguishes an
// added/deleted file from an existing empty file.
type FileVersion struct {
	Exists  bool
	Content []byte
	// Mode is the source file's os.FileMode. Git records only the executable
	// bit for ordinary files; a zero mode preserves the historical 100644
	// default for callers that do not yet provide mode evidence.
	Mode os.FileMode
}

// FilePatch builds a git-compatible unified patch for one repository-relative
// path without touching the caller's worktree or index.
func FilePatch(ctx context.Context, path string, before, after FileVersion) (string, error) {
	if !before.Exists && !after.Exists {
		return "", nil
	}
	cleanPath := filepath.ToSlash(filepath.Clean(path))
	if cleanPath == "" || cleanPath == "." || cleanPath == ".." || strings.HasPrefix(cleanPath, "../") || filepath.IsAbs(cleanPath) {
		return "", fmt.Errorf("invalid patch path %q", path)
	}
	if bytes.Equal(before.Content, after.Content) && before.Exists == after.Exists && gitFileMode(before.Mode) == gitFileMode(after.Mode) {
		return "", nil
	}

	tempDir, err := os.MkdirTemp("", "acta-file-patch-")
	if err != nil {
		return "", fmt.Errorf("create file patch directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	beforePath := filepath.Join(tempDir, "a", filepath.FromSlash(cleanPath))
	afterPath := filepath.Join(tempDir, "b", filepath.FromSlash(cleanPath))
	for _, candidate := range []string{beforePath, afterPath} {
		if err := os.MkdirAll(filepath.Dir(candidate), 0o755); err != nil {
			return "", fmt.Errorf("create file patch parent: %w", err)
		}
	}
	if err := os.WriteFile(beforePath, before.Content, 0o600); err != nil {
		return "", fmt.Errorf("write file patch before image: %w", err)
	}
	if err := os.WriteFile(afterPath, after.Content, 0o600); err != nil {
		return "", fmt.Errorf("write file patch after image: %w", err)
	}
	beforeMode, afterMode := before.Mode, after.Mode
	if !before.Exists {
		beforeMode = afterMode
	}
	if !after.Exists {
		afterMode = beforeMode
	}
	if err := os.Chmod(beforePath, filesystemPatchMode(beforeMode)); err != nil {
		return "", fmt.Errorf("set file patch before mode: %w", err)
	}
	if err := os.Chmod(afterPath, filesystemPatchMode(afterMode)); err != nil {
		return "", fmt.Errorf("set file patch after mode: %w", err)
	}

	cmd := exec.CommandContext(ctx, "git", "diff", "--no-index", "--no-ext-diff", "--binary", "--src-prefix=", "--dst-prefix=", "--", "a/"+cleanPath, "b/"+cleanPath)
	cmd.Dir = tempDir
	cmd.Env = gitEnv()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	stderrLimit := &maxBytesWriter{destination: &stderr, remaining: maxGitDiagnosticBytes, limit: maxGitDiagnosticBytes}
	cmd.Stderr = stderrLimit
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
			return "", fmt.Errorf("generate file patch: %w: %s", err, gitDiagnostic(stderr.String(), stderrLimit.exceeded))
		}
	}
	patch := stdout.String()
	if patch == "" && before.Exists != after.Exists {
		patch = fmt.Sprintf("diff --git a/%s b/%s\n", cleanPath, cleanPath)
	}
	if before.Exists && after.Exists && gitFileMode(before.Mode) != gitFileMode(after.Mode) && !strings.Contains(patch, "\nold mode ") {
		if patch == "" {
			patch = fmt.Sprintf("diff --git a/%s b/%s\n", cleanPath, cleanPath)
		}
		patch = insertPatchMetadata(patch, "new mode "+gitFileMode(after.Mode))
		patch = insertPatchMetadata(patch, "old mode "+gitFileMode(before.Mode))
	}
	if !before.Exists {
		patch = markFileAdded(patch, gitFileMode(after.Mode))
	}
	if !after.Exists {
		patch = markFileDeleted(patch, gitFileMode(before.Mode))
	}
	return patch, nil
}

func filesystemPatchMode(mode os.FileMode) os.FileMode {
	if mode.Perm()&0o111 != 0 {
		return 0o700
	}
	return 0o600
}

func gitFileMode(mode os.FileMode) string {
	if mode.Perm()&0o111 != 0 {
		return "100755"
	}
	return "100644"
}

func insertPatchMetadata(patch, metadata string) string {
	newline := strings.IndexByte(patch, '\n')
	if newline < 0 {
		return patch + "\n" + metadata + "\n"
	}
	return patch[:newline+1] + metadata + "\n" + patch[newline+1:]
}

func replacePatchHeader(patch, marker, replacement string) string {
	start := strings.Index(patch, "\n"+marker)
	if start < 0 {
		return patch
	}
	start++
	end := strings.IndexByte(patch[start:], '\n')
	if end < 0 {
		return patch[:start] + replacement
	}
	return patch[:start] + replacement + patch[start+end:]
}

func markFileAdded(patch, mode string) string {
	patch = insertPatchMetadata(patch, "new file mode "+mode)
	return replacePatchHeader(patch, "--- ", "--- /dev/null")
}

func markFileDeleted(patch, mode string) string {
	patch = insertPatchMetadata(patch, "deleted file mode "+mode)
	return replacePatchHeader(patch, "+++ ", "+++ /dev/null")
}

// WorkspaceDiff streams the combined staged+unstaged+untracked diff for dir
// into destPath and reports whether anything was written. An empty diff leaves
// no file. A non-git dir is a no-op (false, nil) — not every workspace is a
// repo. excludes are workspace-relative paths (forward-slashed) kept out of
// the diff, e.g. the run bundle dir so a run never captures itself.
//
// Untracked staging uses a private snapshot of the repository index. The
// caller's real index is never modified, even transiently, so an interrupted
// capture cannot leave intent-to-add entries behind or race an unrelated Git
// operation. `git add --pathspec-from-file` requires git >=2.25.
func WorkspaceDiff(ctx context.Context, dir, destPath string, excludes ...string) (wrote bool, err error) {
	return WorkspaceDiffWithLimit(ctx, dir, destPath, 0, excludes...)
}

// WorkspaceDiffWithLimit is WorkspaceDiff with an explicit maximum artifact
// size. Zero means unlimited. A limit failure aborts the secure temporary file,
// so callers never observe a partial workspace.diff.
func WorkspaceDiffWithLimit(ctx context.Context, dir, destPath string, maxBytes int64, excludes ...string) (wrote bool, err error) {
	if maxBytes < 0 {
		return false, fmt.Errorf("workspace diff byte limit must not be negative")
	}
	if _, err := git(ctx, dir, "rev-parse", "--git-dir"); err != nil {
		if isNonGitRepoError(err) {
			return false, nil
		}
		return false, fmt.Errorf("detect git repository: %w", err)
	}

	pathspec := append([]string{"."}, excludePathspecs(excludes)...)

	untracked, err := untrackedFiles(ctx, dir, pathspec)
	if err != nil {
		return false, err
	}
	indexFile, cleanupIndex, err := snapshotIndex(ctx, dir)
	if err != nil {
		return false, err
	}
	defer cleanupIndex()
	indexEnv := []string{"GIT_INDEX_FILE=" + indexFile}
	if len(untracked) > 0 {
		if err := gitPathspecStdinEnv(ctx, dir, indexEnv, untracked, "add", "--intent-to-add"); err != nil {
			return false, fmt.Errorf("stage untracked files: %w", err)
		}
	}

	f, err := securefile.Create(destPath)
	if err != nil {
		return false, fmt.Errorf("create workspace diff: %w", err)
	}
	defer f.Abort()
	var destination io.Writer = f
	limited := &maxBytesWriter{destination: f, remaining: maxBytes, limit: maxBytes}
	if maxBytes > 0 {
		destination = limited
	}
	writeErr := streamDiffs(ctx, dir, destination, pathspec, indexEnv)
	if writeErr != nil {
		if limited.exceeded {
			return false, fmt.Errorf("%w: %d-byte limit", ErrWorkspaceDiffLimit, maxBytes)
		}
		return false, writeErr
	}
	size, err := f.Size()
	if err != nil {
		return false, fmt.Errorf("stat workspace diff: %w", err)
	}
	if size == 0 {
		if err := os.Remove(destPath); err != nil && !os.IsNotExist(err) {
			return false, fmt.Errorf("remove empty workspace diff: %w", err)
		}
		return false, nil
	}
	if err := f.Commit(); err != nil {
		return false, fmt.Errorf("commit workspace diff: %w", err)
	}
	return true, nil
}

type maxBytesWriter struct {
	destination io.Writer
	remaining   int64
	limit       int64
	exceeded    bool
}

func (w *maxBytesWriter) Write(payload []byte) (int, error) {
	if int64(len(payload)) > w.remaining {
		w.exceeded = true
		return 0, fmt.Errorf("%w: %d-byte limit", ErrWorkspaceDiffLimit, w.limit)
	}
	written, err := w.destination.Write(payload)
	w.remaining -= int64(written)
	return written, err
}

// Info is the workspace git context recorded as run evidence: whether the
// workspace is a git repository, the commit the run started from (empty until
// the first commit exists), its branch (empty when detached), and whether the
// workspace already had uncommitted or untracked changes.
type Info struct {
	IsRepo    bool
	CommitSHA string
	Branch    string
	Dirty     bool
}

// WorkspaceFiles returns the tracked and untracked, non-ignored files in dir.
// It uses the same bounded context and scrubbed Git environment as the other
// evidence-capture helpers, so inherited repository overrides cannot redirect
// the listing away from dir.
func WorkspaceFiles(ctx context.Context, dir string) ([]string, error) {
	out, err := git(ctx, dir, "ls-files", "-co", "--exclude-standard", "-z")
	if err != nil {
		return nil, fmt.Errorf("list workspace files: %w", err)
	}
	files := make([]string, 0, strings.Count(out, "\x00"))
	for _, name := range strings.Split(out, "\x00") {
		if name != "" {
			files = append(files, name)
		}
	}
	return files, nil
}

// WorkspaceInfo reports dir's git context from a single `git status` call, so
// there is exactly one failure mode: a non-git dir is a no-op (zero Info, nil
// error) and any other git failure is returned rather than recording a
// possibly-wrong context as evidence. excludes follow WorkspaceDiff's
// contract — workspace-relative paths kept out of the dirty check. Nothing is
// implicitly excluded: callers must name the exact generated/control paths so
// legitimate tracked files under similarly named directories remain evidence.
func WorkspaceInfo(ctx context.Context, dir string, excludes ...string) (Info, error) {
	pathspec := append([]string{"."}, excludePathspecs(excludes)...)
	// --untracked-files=normal overrides user config: status.showUntrackedFiles=no
	// would otherwise hide untracked-only dirt that WorkspaceDiff still captures.
	args := append([]string{"status", "--porcelain=v2", "--branch", "--untracked-files=normal", "--"}, pathspec...)
	out, err := git(ctx, dir, args...)
	if err != nil {
		if isNonGitRepoError(err) {
			return Info{}, nil
		}
		return Info{}, fmt.Errorf("read git workspace status: %w", err)
	}
	info := Info{IsRepo: true}
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "# branch.oid "):
			// "(initial)" marks an unborn HEAD: a repo with no commits yet.
			if oid := strings.TrimPrefix(line, "# branch.oid "); oid != "(initial)" {
				info.CommitSHA = oid
			}
		case strings.HasPrefix(line, "# branch.head "):
			// Unlike `rev-parse --abbrev-ref`, branch.head names the branch even on
			// an unborn HEAD and is never disambiguated against same-named tags.
			if head := strings.TrimPrefix(line, "# branch.head "); head != "(detached)" {
				info.Branch = head
			}
		case line != "" && !strings.HasPrefix(line, "#"):
			info.Dirty = true
		}
	}
	return info, nil
}

// HeadCommit returns dir's HEAD commit SHA at call time. A non-git dir or a
// repository with no commits yet yields ("", nil); any other failure is an
// error, so a failed capture is never recorded as "no commits were made".
func HeadCommit(ctx context.Context, dir string) (string, error) {
	sha, err := git(ctx, dir, "rev-parse", "HEAD")
	if err != nil {
		if isNonGitRepoError(err) || isUnbornHeadError(err) {
			return "", nil
		}
		return "", fmt.Errorf("read git HEAD: %w", err)
	}
	return strings.TrimSpace(sha), nil
}

func isUnbornHeadError(err error) bool {
	// `git rev-parse HEAD` before the first commit: "ambiguous argument 'HEAD':
	// unknown revision or path not in the working tree."
	return strings.Contains(strings.ToLower(err.Error()), "unknown revision")
}

func isNonGitRepoError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not a git repository") ||
		strings.Contains(msg, "not a gitdir")
}

func streamDiffs(ctx context.Context, dir string, w io.Writer, pathspec, env []string) error {
	staged := append([]string{"diff", "--cached", "--no-ext-diff", "--binary", "--"}, pathspec...)
	if err := gitStreamEnv(ctx, dir, w, env, staged...); err != nil {
		return fmt.Errorf("staged diff: %w", err)
	}
	unstaged := append([]string{"diff", "--no-ext-diff", "--binary", "--"}, pathspec...)
	if err := gitStreamEnv(ctx, dir, w, env, unstaged...); err != nil {
		return fmt.Errorf("unstaged diff: %w", err)
	}
	return nil
}

// snapshotIndex creates a private index initialized from the caller's current
// index. It deliberately lives outside the repository so Git cannot mistake
// it for worktree content and cleanup is independent of repository mutation.
func snapshotIndex(ctx context.Context, dir string) (string, func(), error) {
	indexPath, err := git(ctx, dir, "rev-parse", "--git-path", "index")
	if err != nil {
		return "", func() {}, fmt.Errorf("resolve git index: %w", err)
	}
	tempDir, err := os.MkdirTemp("", "acta-git-index-")
	if err != nil {
		return "", func() {}, fmt.Errorf("create temporary git index directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tempDir) }
	tempIndex := filepath.Join(tempDir, "index")
	resolvedIndex := strings.TrimSpace(indexPath)
	if !filepath.IsAbs(resolvedIndex) {
		resolvedIndex = filepath.Join(dir, resolvedIndex)
	}
	source, openErr := os.Open(resolvedIndex)
	if openErr == nil {
		destination, createErr := os.OpenFile(tempIndex, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if createErr != nil {
			source.Close()
			cleanup()
			return "", func() {}, fmt.Errorf("create temporary git index: %w", createErr)
		}
		_, copyErr := io.Copy(destination, source)
		closeErr := errors.Join(source.Close(), destination.Close())
		if err := errors.Join(copyErr, closeErr); err != nil {
			cleanup()
			return "", func() {}, fmt.Errorf("copy git index: %w", err)
		}
	} else if !os.IsNotExist(openErr) {
		cleanup()
		return "", func() {}, fmt.Errorf("open git index: %w", openErr)
	}
	return tempIndex, cleanup, nil
}

func excludePathspecs(excludes []string) []string {
	specs := make([]string, 0, len(excludes))
	for _, e := range excludes {
		if e = strings.TrimSpace(e); e != "" && e != "." {
			specs = append(specs, ":(exclude)"+e)
		}
	}
	return specs
}

func untrackedFiles(ctx context.Context, dir string, pathspec []string) ([]string, error) {
	args := append([]string{"ls-files", "--others", "--exclude-standard", "-z", "--"}, pathspec...)
	out, err := git(ctx, dir, args...)
	if err != nil {
		return nil, fmt.Errorf("list untracked files: %w", err)
	}
	var files []string
	for _, name := range strings.Split(out, "\x00") {
		if name != "" {
			files = append(files, name)
		}
	}
	return files, nil
}

// git runs a git command buffering stdout into a string.
func git(ctx context.Context, dir string, args ...string) (string, error) {
	var stdout bytes.Buffer
	limited := &maxBytesWriter{destination: &stdout, remaining: maxBufferedGitOutputBytes, limit: maxBufferedGitOutputBytes}
	if err := gitStream(ctx, dir, limited, args...); err != nil {
		if limited.exceeded {
			return "", fmt.Errorf("git %s output exceeds %d-byte limit", args[0], maxBufferedGitOutputBytes)
		}
		return "", err
	}
	return stdout.String(), nil
}

// gitEnv pins the C locale so git's diagnostics (e.g. "not a git repository")
// stay in English for isNonGitRepoError regardless of the host's LANG/LC_ALL,
// and drops repo-redirection variables so recorded evidence always describes
// the workspace acta was pointed at — not a repository inherited from a git
// hook or CI wrapper environment (GIT_DIR mid-commit would even swap in a
// temporary index).
func gitEnv() []string {
	base := os.Environ()
	env := make([]string, 0, len(base)+1)
	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		switch key {
		case "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
			"GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE":
			continue
		}
		env = append(env, entry)
	}
	return append(env, "LC_ALL=C")
}

// gitStream runs a git command writing stdout straight to w (constant memory,
// so a large --binary diff never materializes in RAM).
func gitStream(ctx context.Context, dir string, w io.Writer, args ...string) error {
	return gitStreamEnv(ctx, dir, w, nil, args...)
}

func gitStreamEnv(ctx context.Context, dir string, w io.Writer, extraEnv []string, args ...string) error {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = append(gitEnv(), extraEnv...)
	cmd.Stdout = w
	var stderr bytes.Buffer
	stderrLimit := &maxBytesWriter{destination: &stderr, remaining: maxGitDiagnosticBytes, limit: maxGitDiagnosticBytes}
	cmd.Stderr = stderrLimit
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git %s: %w: %s", args[0], err, gitDiagnostic(stderr.String(), stderrLimit.exceeded))
	}
	return nil
}

func gitPathspecStdinEnv(ctx context.Context, dir string, extraEnv []string, paths []string, args ...string) error {
	command := args[0]
	args = append(args, "--pathspec-from-file=-", "--pathspec-file-nul")
	// Paths come from `git ls-files`, so every byte is a filename rather than
	// user-authored pathspec syntax. Without --literal-pathspecs, a real file
	// named e.g. `:(top)**` is reinterpreted as pathspec magic; the deferred
	// reset can then reset unrelated staged changes across the whole repository.
	args = append([]string{"--literal-pathspecs"}, args...)
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = append(gitEnv(), extraEnv...)
	cmd.Stdin = strings.NewReader(strings.Join(paths, "\x00"))
	var stderr bytes.Buffer
	stderrLimit := &maxBytesWriter{destination: &stderr, remaining: maxGitDiagnosticBytes, limit: maxGitDiagnosticBytes}
	cmd.Stderr = stderrLimit
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git %s: %w: %s", command, err, gitDiagnostic(stderr.String(), stderrLimit.exceeded))
	}
	return nil
}

func gitDiagnostic(value string, truncated bool) string {
	value = strings.TrimSpace(value)
	if truncated {
		return value + " [stderr truncated at 1048576 bytes]"
	}
	return value
}
