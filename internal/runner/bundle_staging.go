package runner

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/nobbettt/acta/internal/securefile"
)

// Package variables keep publication's filesystem boundary fault-injectable.
// Production always uses the os implementations; tests replace them briefly.
var (
	lookupUserCacheDir = os.UserCacheDir
	lookupUserHomeDir  = os.UserHomeDir
	publishRename      = os.Rename
	publishRemoveAll   = os.RemoveAll
	publishCopyFile    = copyStagedFile
	publishSyncDir     = securefile.SyncDirectory
)

func createBundleStagingDir(cwd string, writableDirs []string) (string, error) {
	var candidates []string
	var result error
	if cacheDir, err := lookupUserCacheDir(); err != nil {
		result = errors.Join(result, fmt.Errorf("resolve user cache directory: %w", err))
	} else {
		candidates = append(candidates, filepath.Join(cacheDir, "acta", "staging"))
	}
	if homeDir, err := lookupUserHomeDir(); err != nil {
		result = errors.Join(result, fmt.Errorf("resolve user home directory: %w", err))
	} else {
		candidates = append(candidates, filepath.Join(homeDir, ".acta", "staging"))
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("resolve protected bundle staging roots: %w", result)
	}
	seen := map[string]bool{}
	for _, root := range candidates {
		root = filepath.Clean(root)
		if seen[root] {
			continue
		}
		seen[root] = true
		stage, err := createBundleStagingAt(root, cwd, writableDirs)
		if err == nil {
			return stage, nil
		}
		result = errors.Join(result, fmt.Errorf("staging root %s: %w", root, err))
	}
	return "", fmt.Errorf("create protected bundle staging directory: %w", result)
}

func createBundleStagingAt(root string, cwd string, writableDirs []string) (string, error) {
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("staging root must be absolute")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", fmt.Errorf("create bundle staging root: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return "", fmt.Errorf("stat bundle staging root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("bundle staging root must be a real directory: %s", root)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return "", fmt.Errorf("secure bundle staging root: %w", err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve bundle staging root: %w", err)
	}
	protectedFrom := append([]string{cwd, os.TempDir()}, writableDirs...)
	for _, writable := range protectedFrom {
		resolvedWritable, err := filepath.EvalSymlinks(writable)
		if err != nil {
			return "", fmt.Errorf("resolve agent-writable directory: %w", err)
		}
		overlaps, err := pathsOverlap(resolvedRoot, resolvedWritable)
		if err != nil {
			return "", err
		}
		if overlaps {
			return "", fmt.Errorf("bundle staging root overlaps an agent-writable or temporary directory: %s", writable)
		}
	}
	stage, err := os.MkdirTemp(resolvedRoot, "run-")
	if err != nil {
		return "", fmt.Errorf("create bundle staging directory: %w", err)
	}
	if err := os.Chmod(stage, 0o700); err != nil {
		_ = os.Remove(stage)
		return "", fmt.Errorf("secure bundle staging directory: %w", err)
	}
	return stage, nil
}

func prepareRunsDir(runsDir string, isDefault bool) (os.FileInfo, error) {
	created := false
	if _, err := os.Lstat(runsDir); os.IsNotExist(err) {
		if err := os.MkdirAll(runsDir, 0o700); err != nil {
			return nil, fmt.Errorf("create runs directory: %w", err)
		}
		created = true
	} else if err != nil {
		return nil, fmt.Errorf("stat runs directory: %w", err)
	}
	info, err := os.Lstat(runsDir)
	if err != nil {
		return nil, fmt.Errorf("stat runs directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("runs directory must be a real directory: %s", runsDir)
	}
	return enforceRunsDirPermissions(runsDir, info, isDefault, created)
}

func verifyRunsDir(runsDir string, expected os.FileInfo) error {
	actual, err := os.Stat(runsDir)
	if err != nil {
		return fmt.Errorf("recheck runs directory: %w", err)
	}
	if !actual.IsDir() || !os.SameFile(expected, actual) {
		return fmt.Errorf("runs directory changed while the agent was running: %s", runsDir)
	}
	return nil
}

func ensureBundleDestinationAvailable(runDir string) error {
	_, err := os.Lstat(runDir)
	switch {
	case err == nil:
		return fmt.Errorf("run directory already exists: %s", runDir)
	case os.IsNotExist(err):
		return nil
	default:
		return fmt.Errorf("stat run directory: %w", err)
	}
}

func publishBundle(stagingDir string, runDir string) (published bool, err error) {
	if err := ensureBundleDestinationAvailable(runDir); err != nil {
		return false, err
	}
	renameErr := publishRename(stagingDir, runDir)
	if renameErr == nil {
		if err := publishSyncDir(filepath.Dir(runDir)); err != nil {
			return true, fmt.Errorf("sync published bundle parent: %w", err)
		}
		return true, nil // stagingDir was already explicitly chmodded to 0700
	}
	if !isCrossDeviceRename(renameErr) {
		return false, fmt.Errorf("rename staged bundle: %w", renameErr)
	}

	// User cache and workspace can live on different filesystems. Fall back to
	// a secure copy into a private sibling. The public run path appears only in
	// the final atomic rename, never as a partially copied directory.
	tempRunDir, err := os.MkdirTemp(filepath.Dir(runDir), "."+filepath.Base(runDir)+".publishing-")
	if err != nil {
		return false, fmt.Errorf("create private publication directory: %w", err)
	}
	if err := os.Chmod(tempRunDir, 0o700); err != nil {
		_ = publishRemoveAll(tempRunDir)
		return false, fmt.Errorf("secure private publication directory: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = publishRemoveAll(tempRunDir)
		}
	}()
	entries, err := os.ReadDir(stagingDir)
	if err != nil {
		return false, fmt.Errorf("read bundle staging directory: %w", err)
	}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
			return false, fmt.Errorf("unexpected staged bundle entry: %s", entry.Name())
		}
		if err := publishCopyFile(filepath.Join(stagingDir, entry.Name()), filepath.Join(tempRunDir, entry.Name())); err != nil {
			return false, fmt.Errorf("publish staged artifact %s: %w", entry.Name(), err)
		}
	}
	if err := publishSyncDir(tempRunDir); err != nil {
		return false, fmt.Errorf("sync copied bundle directory: %w", err)
	}
	if err := publishRename(tempRunDir, runDir); err != nil {
		return false, fmt.Errorf("atomically publish copied bundle: %w", err)
	}
	complete = true
	if err := publishSyncDir(filepath.Dir(runDir)); err != nil {
		return true, fmt.Errorf("sync published bundle parent: %w", err)
	}
	// Publication is complete. A failed source cleanup must never remove or
	// invalidate the final bundle; leaving the protected source is recoverable.
	_ = publishRemoveAll(stagingDir)
	return true, nil
}

func copyStagedFile(source string, destination string) error {
	before, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() {
		return fmt.Errorf("source is not a regular file")
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	after, err := in.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(before, after) {
		return fmt.Errorf("source changed while opening")
	}
	out, err := securefile.CreateExclusive(destination)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeErr := out.Close()
	return errors.Join(copyErr, syncErr, closeErr)
}
