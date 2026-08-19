//go:build !windows

package runner

import (
	"fmt"
	"os"
)

func enforceRunsDirPermissions(path string, inspected os.FileInfo, isDefault, created bool) (os.FileInfo, error) {
	if created || isDefault {
		dir, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open runs directory: %w", err)
		}
		defer dir.Close()
		opened, err := dir.Stat()
		if err != nil {
			return nil, fmt.Errorf("inspect opened runs directory: %w", err)
		}
		if !opened.IsDir() || !os.SameFile(inspected, opened) {
			return nil, fmt.Errorf("runs directory changed while permissions were being checked: %s", path)
		}
		if err := dir.Chmod(0o700); err != nil {
			return nil, fmt.Errorf("secure runs directory: %w", err)
		}
		actual, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("recheck runs directory: %w", err)
		}
		if actual.Mode()&os.ModeSymlink != 0 || !actual.IsDir() || !os.SameFile(inspected, actual) {
			return nil, fmt.Errorf("runs directory changed while permissions were being checked: %s", path)
		}
		return actual, nil
	}
	if inspected.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("runs directory is group/world writable: %s; remove group/other write permissions or choose a private directory", path)
	}
	return inspected, nil
}
