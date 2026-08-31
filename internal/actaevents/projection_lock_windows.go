//go:build windows

package actaevents

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

type projectionLock struct {
	file       *os.File
	overlapped windows.Overlapped
}

func lockProjection(path string) (*projectionLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	lock := &projectionLock{file: file}
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &lock.overlapped); err != nil {
		_ = file.Close()
		return nil, err
	}
	return lock, nil
}

func (lock *projectionLock) close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	return errors.Join(windows.UnlockFileEx(windows.Handle(lock.file.Fd()), 0, 1, 0, &lock.overlapped), lock.file.Close())
}
