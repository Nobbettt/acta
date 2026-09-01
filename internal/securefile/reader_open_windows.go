//go:build windows

package securefile

import (
	"os"

	"golang.org/x/sys/windows"
)

func openRegularFile(path string) (*os.File, error) {
	return openWindowsFile(
		path,
		windows.GENERIC_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
	)
}

func openOrCreateRegularFile(path string) (*os.File, error) {
	return createPrivateFile(path, windows.OPEN_ALWAYS, windows.FILE_FLAG_OPEN_REPARSE_POINT)
}
