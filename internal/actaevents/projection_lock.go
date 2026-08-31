package actaevents

import (
	"context"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"sync"
	"time"
)

const (
	projectionLockRetryMin = 50 * time.Millisecond
	projectionLockRetryMax = 250 * time.Millisecond
)

var projectionLockRegistry = struct {
	sync.Mutex
	locks map[string]*sync.Mutex
}{locks: make(map[string]*sync.Mutex)}

// ProjectionLock serializes projection publication and legacy projection
// snapshots for one run bundle.
type ProjectionLock struct {
	lock  *projectionLock
	local *sync.Mutex
}

// AcquireProjectionLock blocks until the per-bundle projection lock is held.
func AcquireProjectionLock(runDir string) (*ProjectionLock, error) {
	return AcquireProjectionLockContext(context.Background(), runDir)
}

// AcquireProjectionLockContext waits until the per-bundle projection lock is
// held or ctx is cancelled. OS lock attempts are nonblocking so cancellation
// is observed even while another process owns the lock.
func AcquireProjectionLockContext(ctx context.Context, runDir string) (*ProjectionLock, error) {
	local, err := localProjectionMutex(runDir)
	if err != nil {
		return nil, err
	}
	if err := waitForProjectionLockContext(ctx, func() (bool, error) {
		return local.TryLock(), nil
	}); err != nil {
		return nil, err
	}

	var lock *projectionLock
	err = waitForProjectionLockContext(ctx, func() (bool, error) {
		candidate, acquired, tryErr := tryLockProjection(filepath.Join(runDir, ".projection.lock"))
		if acquired {
			lock = candidate
		}
		return acquired, tryErr
	})
	if err != nil {
		local.Unlock()
		return nil, err
	}
	return &ProjectionLock{lock: lock, local: local}, nil
}

// Close releases the OS lock before allowing another goroutine in this process
// to acquire the same bundle lock.
func (lock *ProjectionLock) Close() error {
	if lock == nil || lock.lock == nil {
		return nil
	}
	projectionLock := lock.lock
	local := lock.local
	lock.lock = nil
	lock.local = nil
	err := projectionLock.close()
	local.Unlock()
	return err
}

func localProjectionMutex(runDir string) (*sync.Mutex, error) {
	canonical, err := filepath.Abs(runDir)
	if err != nil {
		return nil, fmt.Errorf("resolve projection lock path: %w", err)
	}
	canonical, err = filepath.EvalSymlinks(canonical)
	if err != nil {
		return nil, fmt.Errorf("resolve projection lock path: %w", err)
	}
	projectionLockRegistry.Lock()
	defer projectionLockRegistry.Unlock()
	lock := projectionLockRegistry.locks[canonical]
	if lock == nil {
		lock = &sync.Mutex{}
		projectionLockRegistry.locks[canonical] = lock
	}
	return lock, nil
}

func waitForProjectionLockContext(ctx context.Context, try func() (bool, error)) error {
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("projection lock held; operation cancelled/timed out: %w", err)
		}
		acquired, err := try()
		if err != nil {
			return err
		}
		if acquired {
			return nil
		}
		jitter := rand.Int64N(int64(projectionLockRetryMax - projectionLockRetryMin + 1))
		timer := time.NewTimer(projectionLockRetryMin + time.Duration(jitter))
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("projection lock held; operation cancelled/timed out: %w", ctx.Err())
		case <-timer.C:
		}
	}
}
