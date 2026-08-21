//go:build !windows

package securefile

import "os"

func createPrivateTemp(dir, pattern string) (*os.File, error) {
	file, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(Mode); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return nil, err
	}
	return file, nil
}

func createPrivateExclusive(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, Mode)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(Mode); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}
