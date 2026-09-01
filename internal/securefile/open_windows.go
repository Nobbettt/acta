//go:build windows

package securefile

import (
	"os"

	"golang.org/x/sys/windows"
)

const regularFileShareMode = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE

var createFile = windows.CreateFile

// openWindowsFile is the single native open path for handles owned by this
// package. In particular, every handle must share delete access so an atomic
// publisher can replace its directory entry while a reader retains the old
// file generation.
func openWindowsFile(path string, access uint32, attributes *windows.SecurityAttributes, disposition uint32, flags uint32) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := createFile(
		name,
		access,
		regularFileShareMode,
		attributes,
		disposition,
		windows.FILE_ATTRIBUTE_NORMAL|flags,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}
