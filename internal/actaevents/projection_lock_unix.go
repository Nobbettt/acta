//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package actaevents

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nobbettt/acta/internal/securefile"
	"golang.org/x/sys/unix"
)

type projectionLock struct {
	file *os.File
}

func tryLockProjection(path string) (*projectionLock, bool, error) {
	file, err := securefile.OpenOrCreateRegular(filepath.Dir(path), path)
	if err != nil {
		return nil, false, fmt.Errorf("open projection lock securely: %w", err)
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
