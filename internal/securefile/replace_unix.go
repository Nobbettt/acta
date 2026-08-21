//go:build !windows

package securefile

import "os"

func replaceFile(source string, target string) error {
	return os.Rename(source, target)
}
