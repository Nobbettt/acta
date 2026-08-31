//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package actaevents

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

type projectionLock struct {
	file *os.File
}

func lockProjection(path string) (*projectionLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &projectionLock{file: file}, nil
}

func (lock *projectionLock) close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	return errors.Join(unix.Flock(int(lock.file.Fd()), unix.LOCK_UN), lock.file.Close())
}
