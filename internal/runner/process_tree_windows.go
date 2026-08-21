//go:build windows

package runner

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsProcessTree struct {
	job windows.Handle
}

func processContainmentName() string { return "windows_job" }

func newProcessTree(cmd *exec.Cmd) (processTree, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)),
		uint32(unsafe.Sizeof(limits)),
	); err != nil {
		_ = windows.CloseHandle(job)
		return nil, err
	}
	// Start suspended so the executable cannot spawn a child before it has been
	// assigned to the kill-on-close job. attach resumes its initial thread only
	// after AssignProcessToJobObject succeeds.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_SUSPENDED}
	return &windowsProcessTree{job: job}, nil
}

func (tree *windowsProcessTree) attach(process *os.Process) error {
	handle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(process.Pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	if err := windows.AssignProcessToJobObject(tree.job, handle); err != nil {
		return err
	}
	return resumeProcessThreads(uint32(process.Pid))
}

func resumeProcessThreads(processID uint32) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	resumed := 0
	for err = windows.Thread32First(snapshot, &entry); err == nil; err = windows.Thread32Next(snapshot, &entry) {
		if entry.OwnerProcessID != processID {
			continue
		}
		thread, openErr := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
		if openErr != nil {
			return openErr
		}
		_, resumeErr := windows.ResumeThread(thread)
		_ = windows.CloseHandle(thread)
		if resumeErr != nil {
			return resumeErr
		}
		resumed++
	}
	if err != nil && err != windows.ERROR_NO_MORE_FILES {
		return err
	}
	if resumed == 0 {
		return fmt.Errorf("no initial thread found for process %d", processID)
	}
	return nil
}

func (tree *windowsProcessTree) kill() error {
	return windows.TerminateJobObject(tree.job, 1)
}

func (tree *windowsProcessTree) close() error {
	return windows.CloseHandle(tree.job)
}
