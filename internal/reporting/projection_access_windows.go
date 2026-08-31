//go:build windows

package reporting

// Windows has no os.Access equivalent. Conservatively keep EACCES fatal;
// EROFS is recognized directly by legacyProjectionLockFreeAllowed.
func projectionDirectoryWritable(string) (bool, error) {
	return true, nil
}
