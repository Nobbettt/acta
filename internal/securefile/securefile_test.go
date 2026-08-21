package securefile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteFileTightensExistingPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "new" {
		t.Fatalf("content = %q, err = %v", got, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != Mode {
			t.Fatalf("mode = %04o, want %04o", got, Mode)
		}
	}
}

func TestCreateExclusiveRejectsExistingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact.json")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if file, err := CreateExclusive(path); err == nil {
		_ = file.Close()
		t.Fatal("CreateExclusive replaced an existing artifact")
	}
}

func TestAtomicWriterAbortPreservesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	writer, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("partial replacement")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Abort(); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "old" {
		t.Fatalf("aborted target = %q, err = %v", got, err)
	}
}

func TestWriteFileReplacesSymlinkInsteadOfFollowingIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require elevated privileges")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	path := filepath.Join(dir, "artifact.json")
	if err := os.WriteFile(target, []byte("preserve"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target.txt", path); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte("artifact")); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "preserve" {
		t.Fatalf("symlink target = %q, err = %v", got, err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("artifact was not replaced by a regular file: info=%v err=%v", info, err)
	}
}

func TestSyncDirectory(t *testing.T) {
	if err := SyncDirectory(t.TempDir()); err != nil {
		t.Fatal(err)
	}
}
