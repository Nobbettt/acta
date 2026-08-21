//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package runner

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

type unixProcessTree struct {
	pid int
}

func processContainmentName() string { return "posix_process_group" }

func newProcessTree(cmd *exec.Cmd) (processTree, error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return &unixProcessTree{}, nil
}

func (tree *unixProcessTree) attach(process *os.Process) error {
	tree.pid = process.Pid
	return nil
}

func (tree *unixProcessTree) kill() error {
	if tree.pid <= 0 {
		return nil
	}
	// POSIX provides portable process-group containment, not a descendant job
	// object. Children that deliberately call setsid/setpgid are outside this
	// contract; callers needing stronger containment must supply it externally
	// (for example a service manager/cgroup).
	err := syscall.Kill(-tree.pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		err = nil
	}
	return err
}

func (*unixProcessTree) close() error { return nil }
