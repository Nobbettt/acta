package securefile

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOpenRegularRejectsSymlinkAndDirectory(t *testing.T) {
	root := t.TempDir()
	if _, err := OpenRegular(root, root); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory error = %v", err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	target := filepath.Join(root, "target.json")
	link := filepath.Join(root, "link.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target.json", link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRegular(root, link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink error = %v", err)
	}
}

// The same contract is required on every platform: in particular, Windows
// must grant delete sharing so projection publication can replace a file while
// a manifested snapshot still holds its old generation open.
func TestOpenRegularAllowsAtomicReplacementWhileOpen(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "projection.json")
	if err := WriteFile(path, []byte("old generation")); err != nil {
		t.Fatal(err)
	}
	opened, err := OpenRegular(root, path)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if err := WriteFile(path, []byte("new generation")); err != nil {
		t.Fatalf("replace file while snapshot handle is open: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "new generation" {
		t.Fatalf("replacement path = %q, %v", got, err)
	}
	if _, err := opened.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(opened); err != nil || string(got) != "old generation" {
		t.Fatalf("open snapshot = %q, %v; want old generation", got, err)
	}
}

func TestReadRegularFileBoundsSize(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "run.json")
	if err := os.WriteFile(path, []byte("oversized"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRegularFile(root, path, 4); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("size error = %v", err)
	}
}
