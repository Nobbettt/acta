package actaevents

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProjectionLockRejectsSymlinkWithoutTouchingTarget(t *testing.T) {
	tests := []struct {
		name           string
		existingTarget bool
	}{
		{name: "nonexistent external target"},
		{name: "existing external target", existingTarget: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runDir := t.TempDir()
			externalPath := filepath.Join(t.TempDir(), "external.lock")
			const original = "external contents must stay unchanged"
			if test.existingTarget {
				if err := os.WriteFile(externalPath, []byte(original), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(externalPath, filepath.Join(runDir, ".projection.lock")); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}

			lock, err := AcquireProjectionLock(runDir)
			if lock != nil || err == nil || !strings.Contains(err.Error(), "projection lock securely") {
				t.Fatalf("AcquireProjectionLock() = %#v, %v; want clear secure-open error", lock, err)
			}
			if !test.existingTarget {
				if _, err := os.Lstat(externalPath); !os.IsNotExist(err) {
					t.Fatalf("external target was created, stat error = %v", err)
				}
				return
			}
			payload, err := os.ReadFile(externalPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(payload) != original {
				t.Fatalf("external target changed to %q", payload)
			}
			externalLock, acquired, err := tryLockProjection(externalPath)
			if err != nil || !acquired {
				t.Fatalf("external target remained locked: acquired=%v error=%v", acquired, err)
			}
			if err := externalLock.close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProjectionLockCreatesAndReopensRegularFile(t *testing.T) {
	runDir := t.TempDir()
	lock, err := AcquireProjectionLock(runDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(runDir, ".projection.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("projection lock mode = %v, want regular file", info.Mode())
	}
	lock, err = AcquireProjectionLock(runDir)
	if err != nil {
		t.Fatalf("reopen regular projection lock: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}
