//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package runner

import (
	"errors"
	"os"
	"os/exec"
)

type directProcessTree struct {
	process *os.Process
}

func processContainmentName() string { return "direct_process" }

func newProcessTree(_ *exec.Cmd) (processTree, error) { return &directProcessTree{}, nil }

func (tree *directProcessTree) attach(process *os.Process) error {
	tree.process = process
	return nil
}

func (tree *directProcessTree) kill() error {
	if tree.process == nil {
		return nil
	}
	if err := tree.process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}

func (*directProcessTree) close() error { return nil }
