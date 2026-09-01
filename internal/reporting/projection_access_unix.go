//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package reporting

import (
	"errors"

	"golang.org/x/sys/unix"
)

func projectionDirectoryWritable(path string) (bool, error) {
	err := unix.Access(path, unix.W_OK)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EROFS) {
		return false, nil
	}
	return false, err
}
