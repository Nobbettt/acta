//go:build !windows

package securefile

import (
	"errors"
	"os"
)

// ValidatePrivate verifies the platform privacy contract for an open file.
// On Unix, sensitive files must have exactly owner-read/write permissions.
func ValidatePrivate(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Mode().Perm() != Mode {
		return errors.New("file mode must be 0600")
	}
	return nil
}
