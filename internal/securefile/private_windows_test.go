//go:build windows

package securefile

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestValidatePrivateUsesWindowsDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.json")
	if err := WriteFile(path, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePrivate(file); err != nil {
		_ = file.Close()
		t.Fatalf("ValidatePrivate(private DACL) error = %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := grantEveryoneRead(path); err != nil {
		t.Fatal(err)
	}
	file, err = os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := ValidatePrivate(file); err == nil {
		t.Fatal("ValidatePrivate(public DACL) unexpectedly succeeded")
	}
}

func grantEveryoneRead(path string) error {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		return err
	}
	dacl, err = windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_READ,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(everyone),
		},
	}}, dacl)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)
}
