//go:build aix

package actaevents

import (
	"errors"
	"io"
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
	request := unix.Flock_t{Type: unix.F_WRLCK, Whence: io.SeekStart, Len: 1}
	if err := unix.FcntlFlock(file.Fd(), unix.F_SETLKW, &request); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &projectionLock{file: file}, nil
}

func (lock *projectionLock) close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	request := unix.Flock_t{Type: unix.F_UNLCK, Whence: io.SeekStart, Len: 1}
	return errors.Join(unix.FcntlFlock(lock.file.Fd(), unix.F_SETLK, &request), lock.file.Close())
}
