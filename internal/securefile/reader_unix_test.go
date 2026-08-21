//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package securefile

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestOpenRegularRejectsFIFOWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "acta-events.jsonl")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRegular(root, path); err == nil || !strings.Contains(err.Error(), "special file") {
		t.Fatalf("FIFO error = %v", err)
	}
}
