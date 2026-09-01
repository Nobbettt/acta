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
// Windows handles permit delete sharing so atomic replacement remains possible
// while a reader holds the returned file open.
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
	file, err := openRegularFile(path)
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

// OpenOrCreateRegular opens path read-write, creating it with owner-only
// permissions when absent, without following a final symlink. The returned
// handle and the path are verified to identify a regular file beneath root.
func OpenOrCreateRegular(root string, path string) (*os.File, error) {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve root: %w", err)
	}
	resolvedParent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("resolve file parent: %w", err)
	}
	if !withinRoot(resolvedRoot, resolvedParent, true) {
		return nil, errors.New("file parent resolves outside the allowed root")
	}
	if before, err := os.Lstat(path); err == nil {
		if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
			return nil, errors.New("file must be a regular file, not a symlink or special file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	file, err := openOrCreateRegularFile(path)
	if err != nil {
		return nil, fmt.Errorf("open regular file without following links: %w", err)
	}
	closeWith := func(err error) (*os.File, error) {
		_ = file.Close()
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() {
		return closeWith(errors.New("opened file must be a regular file"))
	}
	current, err := os.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(current, after) {
		return closeWith(errors.New("file changed while opening or creating"))
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return closeWith(err)
	}
	if !withinRoot(resolvedRoot, resolved, false) {
		return closeWith(errors.New("file resolves outside the allowed root"))
	}
	return file, nil
}

func withinRoot(root, path string, allowRoot bool) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return false
	}
	return allowRoot || rel != "."
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
