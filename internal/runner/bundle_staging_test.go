package runner

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func withPublicationHooks(t *testing.T) {
	t.Helper()
	originalRename := publishRename
	originalRemoveAll := publishRemoveAll
	originalCopyFile := publishCopyFile
	originalSyncDir := publishSyncDir
	t.Cleanup(func() {
		publishRename = originalRename
		publishRemoveAll = originalRemoveAll
		publishCopyFile = originalCopyFile
		publishSyncDir = originalSyncDir
	})
}

func withStagingLookupHooks(t *testing.T) {
	t.Helper()
	originalCache := lookupUserCacheDir
	originalHome := lookupUserHomeDir
	t.Cleanup(func() {
		lookupUserCacheDir = originalCache
		lookupUserHomeDir = originalHome
	})
}

func TestCreateBundleStagingTriesResolvedRootWhenOtherLookupFails(t *testing.T) {
	withStagingLookupHooks(t)
	base, err := os.MkdirTemp(".", ".acta-staging-lookup-test-")
	if err != nil {
		t.Fatal(err)
	}
	base, err = filepath.Abs(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	lookupUserCacheDir = func() (string, error) { return base, nil }
	lookupUserHomeDir = func() (string, error) { return "", errors.New("injected home lookup failure") }

	stage, err := createBundleStagingDir(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("valid cache root was not tried after home lookup failure: %v", err)
	}
	if !strings.HasPrefix(stage, filepath.Join(base, "acta", "staging")) {
		t.Fatalf("staging path = %q, want cache candidate", stage)
	}
}

func TestCreateBundleStagingUsesHomeWhenCacheLookupFails(t *testing.T) {
	withStagingLookupHooks(t)
	base, err := os.MkdirTemp(".", ".acta-staging-home-test-")
	if err != nil {
		t.Fatal(err)
	}
	base, err = filepath.Abs(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	lookupUserCacheDir = func() (string, error) { return "", errors.New("injected cache lookup failure") }
	lookupUserHomeDir = func() (string, error) { return base, nil }

	stage, err := createBundleStagingDir(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("valid home root was not tried after cache lookup failure: %v", err)
	}
	if !strings.HasPrefix(stage, filepath.Join(base, ".acta", "staging")) {
		t.Fatalf("staging path = %q, want home candidate", stage)
	}
}

func stagedBundle(t *testing.T) (string, string) {
	t.Helper()
	parent := t.TempDir()
	staging := filepath.Join(parent, "staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "raw.jsonl"), []byte("complete\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return staging, filepath.Join(parent, "run-final")
}

func TestPublishBundleDoesNotFallbackForOrdinaryRenameError(t *testing.T) {
	withPublicationHooks(t)
	staging, runDir := stagedBundle(t)
	publishRename = func(_, _ string) error { return os.ErrPermission }

	_, err := publishBundle(staging, runDir)
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("publish error = %v, want permission error", err)
	}
	if _, err := os.Stat(runDir); !os.IsNotExist(err) {
		t.Fatalf("ordinary rename error exposed destination, stat error = %v", err)
	}
	if _, err := os.Stat(staging); err != nil {
		t.Fatalf("recoverable staging directory was removed: %v", err)
	}
}

func TestPublishBundleCrossDeviceCopyIsAtomic(t *testing.T) {
	withPublicationHooks(t)
	staging, runDir := stagedBundle(t)
	renames := 0
	publishRename = func(oldPath, newPath string) error {
		renames++
		if renames == 1 {
			return &os.LinkError{Op: "rename", Old: oldPath, New: newPath, Err: syscall.EXDEV}
		}
		return os.Rename(oldPath, newPath)
	}
	publishCopyFile = func(source, destination string) error {
		if _, err := os.Stat(runDir); !os.IsNotExist(err) {
			t.Fatalf("final destination became visible during copy: %v", err)
		}
		return copyStagedFile(source, destination)
	}

	if _, err := publishBundle(staging, runDir); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(runDir, "raw.jsonl")); err != nil || string(got) != "complete\n" {
		t.Fatalf("published content = %q, err = %v", got, err)
	}
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		t.Fatalf("successful publication left staging directory, stat error = %v", err)
	}
}

func TestPublishBundleCopyFailureLeavesNoPartialDestination(t *testing.T) {
	withPublicationHooks(t)
	staging, runDir := stagedBundle(t)
	publishRename = func(oldPath, newPath string) error {
		return &os.LinkError{Op: "rename", Old: oldPath, New: newPath, Err: syscall.EXDEV}
	}
	publishCopyFile = func(_, _ string) error { return errors.New("injected copy failure") }

	if _, err := publishBundle(staging, runDir); err == nil {
		t.Fatal("copy failure unexpectedly succeeded")
	}
	if _, err := os.Stat(runDir); !os.IsNotExist(err) {
		t.Fatalf("copy failure exposed partial destination, stat error = %v", err)
	}
	if _, err := os.Stat(staging); err != nil {
		t.Fatalf("copy failure removed recoverable staging: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(runDir), ".run-final.publishing-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("private copy directories after failure = %v, err = %v", matches, err)
	}
}

func TestPublishBundleCleanupFailureKeepsCompletedCopy(t *testing.T) {
	withPublicationHooks(t)
	staging, runDir := stagedBundle(t)
	renames := 0
	publishRename = func(oldPath, newPath string) error {
		renames++
		if renames == 1 {
			return syscall.EXDEV
		}
		return os.Rename(oldPath, newPath)
	}
	publishRemoveAll = func(path string) error {
		if path == staging {
			return errors.New("injected cleanup failure")
		}
		return os.RemoveAll(path)
	}

	if _, err := publishBundle(staging, runDir); err != nil {
		t.Fatalf("completed publication failed because source cleanup failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(runDir, "raw.jsonl")); err != nil {
		t.Fatalf("completed copy was not retained: %v", err)
	}
	if _, err := os.Stat(staging); err != nil {
		t.Fatalf("failed source cleanup should leave recoverable staging: %v", err)
	}
}

func TestPublishBundleReportsCompletedRenameWhenParentSyncFails(t *testing.T) {
	withPublicationHooks(t)
	staging, runDir := stagedBundle(t)
	publishSyncDir = func(string) error { return errors.New("injected parent sync failure") }

	published, err := publishBundle(staging, runDir)
	if err == nil || !published {
		t.Fatalf("publish result published=%v err=%v, want completed rename with durability error", published, err)
	}
	if _, err := os.Stat(filepath.Join(runDir, "raw.jsonl")); err != nil {
		t.Fatalf("published bundle missing after sync error: %v", err)
	}
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		t.Fatalf("renamed staging unexpectedly remains: %v", err)
	}
}
