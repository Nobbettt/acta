//go:build !windows

package securefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidatePrivateRequiresMode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.json")
	if err := os.WriteFile(path, []byte("{}"), Mode); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := ValidatePrivate(file); err != nil {
		t.Fatalf("ValidatePrivate(0600) error = %v", err)
	}
	for _, mode := range []os.FileMode{0o400, 0o640, 0o644} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := ValidatePrivate(file); err == nil {
			t.Errorf("ValidatePrivate(%04o) unexpectedly succeeded", mode)
		}
	}
}
