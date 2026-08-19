package securefile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// OpenRegular opens path only when it is a stable regular file resolving
// beneath root. It rejects final and intermediate symlink escapes, FIFOs,
// devices, directories, and replacement races between inspection and open.
func OpenRegular(root string, path string) (*os.File, error) {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve root: %w", err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("file must be a regular file, not a symlink or special file")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(resolvedRoot, resolved)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return nil, errors.New("file resolves outside the allowed root")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, errors.New("file changed while opening")
	}
	return file, nil
}

func ReadRegularFile(root string, path string, maxBytes int64) ([]byte, error) {
	file, err := OpenRegular(root, path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("file exceeds %d-byte limit", maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file exceeds %d-byte limit", maxBytes)
	}
	return data, nil
}
