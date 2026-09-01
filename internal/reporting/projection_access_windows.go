//go:build windows

package reporting

import (
	"errors"
	"os"

	"github.com/nobbettt/acta/internal/securefile"
	"golang.org/x/sys/windows"
)

func projectionDirectoryWritable(path string) (bool, error) {
	return probeProjectionDirectoryWritable(path, securefile.CreateTemp, os.Remove, func(err error) bool {
		return errors.Is(err, os.ErrPermission) || errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_WRITE_PROTECT)
	})
}
