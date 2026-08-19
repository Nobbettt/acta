package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

type processTree interface {
	attach(*os.Process) error
	kill() error
	close() error
}

// runProcessTree starts cmd in a platform-specific process container and owns
// cancellation itself. Windows uses a Job Object; POSIX systems use a process
// group (which deliberately does not claim containment of children that call
// setsid/setpgid); other platforms fall back to the direct process.
func runProcessTree(ctx context.Context, cmd *exec.Cmd) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tree, err := newProcessTree(cmd)
	if err != nil {
		return fmt.Errorf("prepare process tree: %w", err)
	}
	closeTree := func() error { return tree.close() }

	if err := cmd.Start(); err != nil {
		return errors.Join(err, closeTree())
	}
	if err := tree.attach(cmd.Process); err != nil {
		killErr := cmd.Process.Kill()
		waitErr := cmd.Wait()
		return errors.Join(fmt.Errorf("attach agent process tree: %w", err), killErr, waitErr, closeTree())
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var runErr error
	select {
	case runErr = <-done:
	case <-ctx.Done():
		killErr := tree.kill()
		runErr = <-done
		if runErr == nil {
			runErr = ctx.Err()
		}
		runErr = errors.Join(runErr, killErr)
	}

	// Also clean up remaining process-container members if the direct agent exits
	// without waiting for them. Platform implementations make kill idempotent
	// and ignore an already empty process group/job.
	return errors.Join(runErr, tree.kill(), closeTree())
}
