//go:build windows

package securefile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const privateTempAttempts = 100

func createPrivateTemp(dir, pattern string) (*os.File, error) {
	for range privateTempAttempts {
		suffix := make([]byte, 8)
		if _, err := rand.Read(suffix); err != nil {
			return nil, fmt.Errorf("generate temporary file name: %w", err)
		}
		name := strings.Replace(pattern, "*", hex.EncodeToString(suffix), 1)
		file, err := createPrivateExclusive(filepath.Join(dir, name))
		if err == nil {
			return file, nil
		}
		if !errors.Is(err, windows.ERROR_FILE_EXISTS) && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return nil, err
		}
	}
	return nil, errors.New("could not create a unique private temporary file")
}

func createPrivateExclusive(path string) (*os.File, error) {
	return createPrivateFile(path, windows.CREATE_NEW, 0)
}

func createPrivateFile(path string, disposition uint32, flags uint32) (*os.File, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read current user for private file: %w", err)
	}
	sddl := fmt.Sprintf("O:%sD:P(A;;GA;;;%s)(A;;GA;;;SY)(A;;GA;;;BA)", user.User.Sid.String(), user.User.Sid.String())
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("build private file security descriptor: %w", err)
	}
	defer runtime.KeepAlive(descriptor)
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	return openWindowsFile(
		path,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		&attributes,
		disposition,
		flags,
	)
}
