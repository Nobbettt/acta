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

func tryLockProjection(path string) (*projectionLock, bool, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, err
	}
	lock := &projectionLock{file: file}
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK | windows.LOCKFILE_FAIL_IMMEDIATELY)
	if err := windows.LockFileEx(windows.Handle(file.Fd()), flags, 0, 1, 0, &lock.overlapped); err != nil {
		closeErr := file.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, false, closeErr
		}
		return nil, false, errors.Join(err, closeErr)
	}
	return lock, true, nil
}

func (lock *projectionLock) close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	return errors.Join(windows.UnlockFileEx(windows.Handle(lock.file.Fd()), 0, 1, 0, &lock.overlapped), lock.file.Close())
}
