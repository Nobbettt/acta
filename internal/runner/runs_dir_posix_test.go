//go:build !windows

package runner

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestPrepareRunsDirPermissionPolicy(t *testing.T) {
	oldUmask := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(oldUmask) })

	t.Run("missing default is private", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "default")
		if _, err := prepareRunsDir(path, true); err != nil {
			t.Fatal(err)
		}
		assertMode(t, path, 0o700)
	})

	t.Run("existing default is tightened", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "default")
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := prepareRunsDir(path, true); err != nil {
			t.Fatal(err)
		}
		assertMode(t, path, 0o700)
	})

	t.Run("missing custom is private", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "custom")
		if _, err := prepareRunsDir(path, false); err != nil {
			t.Fatal(err)
		}
		assertMode(t, path, 0o700)
	})

	for _, mode := range []os.FileMode{0o755, 0o750} {
		mode := mode
		t.Run("existing custom accepted "+mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "custom")
			if err := os.Mkdir(path, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := prepareRunsDir(path, false); err != nil {
				t.Fatal(err)
			}
			assertMode(t, path, mode)
		})
	}

	for _, mode := range []uint32{0o775, 0o777, 0o1777} {
		mode := mode
		t.Run("writable custom rejected", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "custom")
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			_, err := prepareRunsDir(path, false)
			if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "remove group/other write permissions") {
				t.Fatalf("prepareRunsDir() error = %v, want actionable writable-root rejection", err)
			}
			info, statErr := os.Stat(path)
			if statErr != nil {
				t.Fatal(statErr)
			}
			if got := uint32(info.Mode().Perm()); got != mode&0o777 {
				t.Fatalf("mode changed to %#o, want %#o", got, mode&0o777)
			}
			if mode&0o1000 != 0 && info.Mode()&os.ModeSticky == 0 {
				t.Fatal("sticky bit was changed")
			}
		})
	}
}
