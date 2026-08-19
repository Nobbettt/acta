//go:build !windows

package runtimebundle

import "os"

func makeBundlePublic(path string) error {
	return os.Chmod(path, 0o644)
}

func writePrivateBundle(path string, payload []byte) error {
	return os.WriteFile(path, payload, 0o600)
}

func makeBundlePrivate(path string, _ []byte) error {
	return os.Chmod(path, 0o600)
}
