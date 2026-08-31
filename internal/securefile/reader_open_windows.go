//go:build windows

package securefile

import (
	"os"

	"golang.org/x/sys/windows"
)

const regularFileShareMode = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE

func openRegularFile(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ,
		regularFileShareMode,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}

func openOrCreateRegularFile(path string) (*os.File, error) {
	return createPrivateFile(path, windows.OPEN_ALWAYS, windows.FILE_FLAG_OPEN_REPARSE_POINT)
}
