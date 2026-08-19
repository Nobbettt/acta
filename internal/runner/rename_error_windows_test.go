//go:build windows

package runner

import (
	"errors"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestIsCrossDeviceRenameWindowsErrors(t *testing.T) {
	for _, err := range []error{
		&os.LinkError{Op: "rename", Old: `C:\stage`, New: `D:\run`, Err: windows.ERROR_NOT_SAME_DEVICE},
		&os.LinkError{Op: "rename", Old: `C:\stage`, New: `D:\run`, Err: syscall.EXDEV},
	} {
		if !isCrossDeviceRename(err) {
			t.Errorf("isCrossDeviceRename(%v) = false", err)
		}
	}
	if isCrossDeviceRename(&os.LinkError{Op: "rename", Err: os.ErrPermission}) {
		t.Fatal("permission error was misclassified as cross-device")
	}
	if isCrossDeviceRename(errors.New("invalid cross-device link")) {
		t.Fatal("diagnostic text without a typed error was misclassified")
	}
}
