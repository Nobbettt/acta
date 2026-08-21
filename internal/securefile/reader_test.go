package securefile

import (
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
