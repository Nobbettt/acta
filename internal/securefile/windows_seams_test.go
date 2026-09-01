//go:build windows

package securefile

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func TestOpenWindowsFileRequestsDeleteSharingAndReparsePointProtection(t *testing.T) {
	originalCreateFile := createFile
	t.Cleanup(func() { createFile = originalCreateFile })
	injected := errors.New("injected CreateFile failure")
	createFile = func(
		_ *uint16,
		access uint32,
		shareMode uint32,
		_ *windows.SecurityAttributes,
		disposition uint32,
		flags uint32,
		_ windows.Handle,
	) (windows.Handle, error) {
		if access != windows.GENERIC_READ {
			t.Errorf("access = %#x, want GENERIC_READ", access)
		}
		if shareMode != windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE {
			t.Errorf("share mode = %#x, want read/write/delete sharing", shareMode)
		}
		if disposition != windows.OPEN_EXISTING {
			t.Errorf("disposition = %#x, want OPEN_EXISTING", disposition)
		}
		wantFlags := uint32(windows.FILE_ATTRIBUTE_NORMAL | windows.FILE_FLAG_OPEN_REPARSE_POINT)
		if flags != wantFlags {
			t.Errorf("flags = %#x, want %#x", flags, wantFlags)
		}
		return windows.InvalidHandle, injected
	}

	if _, err := openRegularFile(`C:\bundle\run.json`); !errors.Is(err, injected) {
		t.Fatalf("openRegularFile() error = %v, want injected native error", err)
	}
}

func TestMoveFileExRequestsAtomicReplacement(t *testing.T) {
	originalMoveFileEx := moveFileExCall
	t.Cleanup(func() { moveFileExCall = originalMoveFileEx })
	called := false
	moveFileExCall = func(_, _ *uint16, flags uint32) error {
		called = true
		wantFlags := uint32(windows.MOVEFILE_REPLACE_EXISTING | windows.MOVEFILE_WRITE_THROUGH)
		if flags != wantFlags {
			t.Errorf("MoveFileEx flags = %#x, want %#x", flags, wantFlags)
		}
		return nil
	}

	if err := moveFileEx(`C:\bundle\source.tmp`, `C:\bundle\run.json`); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("MoveFileEx seam was not called")
	}
}
