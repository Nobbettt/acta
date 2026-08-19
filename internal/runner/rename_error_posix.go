//go:build !windows

package runner

import (
	"errors"
	"syscall"
)

func isCrossDeviceRename(err error) bool { return errors.Is(err, syscall.EXDEV) }
