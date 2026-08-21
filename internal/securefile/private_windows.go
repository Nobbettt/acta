//go:build windows

package securefile

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	accessAllowedCompoundACEType       = 4
	accessAllowedObjectACEType         = 5
	accessAllowedCallbackACEType       = 9
	accessAllowedCallbackObjectACEType = 11
)

// ValidatePrivate verifies the platform privacy contract for an open file.
// Windows permission bits are synthetic, so privacy is defined by the native
// security descriptor: the current user must own the file and only that user,
// Local System, or built-in Administrators may receive access through its DACL.
func ValidatePrivate(file *os.File) error {
	descriptor, err := windows.GetSecurityInfo(
		windows.Handle(file.Fd()),
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("read file security descriptor: %w", err)
	}
	defer runtime.KeepAlive(descriptor)
	owner, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("read file owner: %w", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("read current user: %w", err)
	}
	defer runtime.KeepAlive(user)
	if owner == nil || !owner.Equals(user.User.Sid) {
		return errors.New("file owner is not the current user")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read file DACL: %w", err)
	}
	if dacl == nil {
		return errors.New("file has a permissive null DACL")
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return fmt.Errorf("read file DACL entry: %w", err)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !allowedPrivatePrincipal(sid, user.User.Sid) {
				return fmt.Errorf("file DACL grants access to %s", sid.String())
			}
		case accessAllowedCompoundACEType, accessAllowedObjectACEType, accessAllowedCallbackACEType, accessAllowedCallbackObjectACEType:
			return errors.New("file DACL contains an unsupported access-allowed entry")
		}
	}
	return nil
}

func allowedPrivatePrincipal(candidate, user *windows.SID) bool {
	return candidate.Equals(user) ||
		candidate.IsWellKnown(windows.WinLocalSystemSid) ||
		candidate.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}
