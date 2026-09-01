//go:build aix

package actaevents

import (
	"errors"
	"fmt"
	"io"
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
	request := unix.Flock_t{Type: unix.F_WRLCK, Whence: io.SeekStart, Len: 1}
	if err := unix.FcntlFlock(file.Fd(), unix.F_SETLK, &request); err != nil {
		closeErr := file.Close()
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EAGAIN) {
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
	request := unix.Flock_t{Type: unix.F_UNLCK, Whence: io.SeekStart, Len: 1}
	return errors.Join(unix.FcntlFlock(lock.file.Fd(), unix.F_SETLK, &request), lock.file.Close())
}
