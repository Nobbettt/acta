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

// Every opener must grant delete sharing on Windows so projection publication
// can replace a file while a handle still holds its old generation open.
func TestWritableRegularHandlesAllowAtomicReplacementWhileOpen(t *testing.T) {
	tests := []struct {
		name           string
		readable       bool
		seedBeforeOpen bool
		open           func(string, string) (*os.File, error)
	}{
		{name: "read only", readable: true, seedBeforeOpen: true, open: OpenRegular},
		{
			name: "exclusive",
			open: func(_ string, path string) (*os.File, error) {
				return CreateExclusive(path)
			},
		},
		{
			name:     "temporary",
			readable: true,
			open: func(root string, _ string) (*os.File, error) {
				return CreateTemp(root, "projection-*")
			},
		},
		{
			name:     "open or create",
			readable: true,
			open: func(root string, path string) (*os.File, error) {
				return OpenOrCreateRegular(root, path)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "projection.json")
			if test.seedBeforeOpen {
				if err := WriteFile(path, []byte("old generation")); err != nil {
					t.Fatal(err)
				}
			}
			opened, err := test.open(root, path)
			if err != nil {
				t.Fatal(err)
			}
			defer opened.Close()
			path = opened.Name()
			if !test.seedBeforeOpen {
				if _, err := opened.Write([]byte("old generation")); err != nil {
					t.Fatal(err)
				}
			}
			if err := WriteFile(path, []byte("new generation")); err != nil {
				t.Fatalf("replace file while secure writable handle is open: %v", err)
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != "new generation" {
				t.Fatalf("replacement path = %q, %v", got, err)
			}
			info, err := opened.Stat()
			if err != nil || info.Size() != int64(len("old generation")) {
				t.Fatalf("open old generation size = %v, %v", info, err)
			}
			if !test.readable {
				return
			}
			if _, err := opened.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			if got, err := io.ReadAll(opened); err != nil || string(got) != "old generation" {
				t.Fatalf("open snapshot = %q, %v; want old generation", got, err)
			}
		})
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
