//go:build windows

package runner

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

func isCrossDeviceRename(err error) bool {
	// os.Rename reports ERROR_NOT_SAME_DEVICE on Windows. syscall.EXDEV is
	// retained as the portable Go-level equivalent used by injected filesystem
	// implementations and tests; no other rename failure triggers copying.
	return errors.Is(err, windows.ERROR_NOT_SAME_DEVICE) || errors.Is(err, syscall.EXDEV)
}
