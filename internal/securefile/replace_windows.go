//go:build windows

package securefile

import (
	"errors"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

var moveFileExCall = windows.MoveFileEx

func replaceFile(source string, target string) error {
	return replaceFileWithFallback(source, target, moveFileEx, replaceOpenTarget, func(err error) bool {
		return errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)
	})
}

func moveFileEx(source string, target string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return moveFileExCall(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// Windows 11 24H2 and Windows Server 2025 can reject MoveFileEx replacement
// of an open destination even when every live handle shares delete access.
// FILE_RENAME_POSIX_SEMANTICS provides the required replace-while-open
// behavior on those systems while retaining the old generation for readers.
func replaceOpenTarget(source string, target string) error {
	sourceFile, err := openWindowsFile(
		source,
		windows.DELETE|windows.SYNCHRONIZE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
	)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	target, err = filepath.Abs(target)
	if err != nil {
		return err
	}
	targetName, err := windows.UTF16FromString(target)
	if err != nil {
		return err
	}
	targetName = targetName[:len(targetName)-1]

	type fileRenameInfo struct {
		Flags          uint32
		RootDirectory  windows.Handle
		FileNameLength uint32
		FileName       [1]uint16
	}
	var layout fileRenameInfo
	nameOffset := int(unsafe.Offsetof(layout.FileName))
	buffer := make([]byte, nameOffset+len(targetName)*2)
	info := (*fileRenameInfo)(unsafe.Pointer(&buffer[0]))
	info.Flags = windows.FILE_RENAME_REPLACE_IF_EXISTS | windows.FILE_RENAME_POSIX_SEMANTICS
	info.FileNameLength = uint32(len(targetName) * 2)
	copy(unsafe.Slice(&info.FileName[0], len(targetName)), targetName)

	return windows.SetFileInformationByHandle(
		windows.Handle(sourceFile.Fd()),
		windows.FileRenameInfoEx,
		&buffer[0],
		uint32(len(buffer)),
	)
}
