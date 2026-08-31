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

func tryLockProjection(path string) (*projectionLock, bool, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		closeErr := file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, false, closeErr
		}
		return nil, false, errors.Join(err, closeErr)
	}
	return &projectionLock{file: file}, true, nil
}

func (lock *projectionLock) close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	return errors.Join(unix.Flock(int(lock.file.Fd()), unix.LOCK_UN), lock.file.Close())
}
