// Package securefile creates sensitive run artifacts with owner-only access.
package securefile

import (
	"errors"
	"os"
	"path/filepath"
)

const Mode os.FileMode = 0o600

type AtomicWriter struct {
	file           *os.File
	temporary      string
	target         string
	replace        func(string, string) error
	syncDirectory  func(string) error
	committed      bool
	targetReplaced bool
}

// Create starts an atomic rewrite beside path. Commit replaces path without
// following it when path is a symlink; Abort leaves the previous path intact.
func Create(path string) (*AtomicWriter, error) {
	dir := filepath.Dir(path)
	file, err := createPrivateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return nil, err
	}
	return &AtomicWriter{
		file: file, temporary: file.Name(), target: path,
		replace: replaceFile, syncDirectory: SyncDirectory,
	}, nil
}

func CreateExclusive(path string) (*os.File, error) {
	return createPrivateExclusive(path)
}

// CreateTemp creates a uniquely named owner-only file in dir. The pattern must
// contain one '*', which is replaced with random text.
func CreateTemp(dir, pattern string) (*os.File, error) {
	return createPrivateTemp(dir, pattern)
}

func (writer *AtomicWriter) Write(data []byte) (int, error) {
	return writer.file.Write(data)
}

func (writer *AtomicWriter) Size() (int64, error) {
	info, err := writer.file.Stat()
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func (writer *AtomicWriter) Commit() error {
	if writer.committed {
		return errors.New("secure file already committed")
	}
	if err := writer.file.Sync(); err != nil {
		_ = writer.Abort()
		return err
	}
	if err := writer.file.Close(); err != nil {
		_ = os.Remove(writer.temporary)
		return err
	}
	directory := filepath.Dir(writer.target)
	// Surface a directory-sync failure while the original target is still
	// intact. A second sync after rename makes the replacement durable; callers
	// can distinguish that ambiguous failure via TargetReplaced.
	if err := writer.syncDirectory(directory); err != nil {
		_ = os.Remove(writer.temporary)
		return err
	}
	if err := writer.replace(writer.temporary, writer.target); err != nil {
		_ = os.Remove(writer.temporary)
		return err
	}
	writer.targetReplaced = true
	writer.committed = true
	return writer.syncDirectory(directory)
}

// TargetReplaced reports whether Commit completed the atomic rename. When it
// returns true alongside a Commit error, the target contains the complete
// replacement but its directory entry may not be durable.
func (writer *AtomicWriter) TargetReplaced() bool {
	return writer != nil && writer.targetReplaced
}

func (writer *AtomicWriter) Abort() error {
	if writer == nil || writer.committed {
		return nil
	}
	return errors.Join(writer.file.Close(), os.Remove(writer.temporary))
}

func WriteFile(path string, data []byte) error {
	writer, err := Create(path)
	if err != nil {
		return err
	}
	defer writer.Abort()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}

// ReplaceFile atomically moves source over target, including when target
// already exists. On Windows the replacement is requested with write-through
// semantics.
func ReplaceFile(source, target string) error {
	return replaceFile(source, target)
}

// SyncDirectory makes a successful atomic replacement durable at the
// directory-entry level on platforms which require an explicit directory
// fsync. Windows replaceFile already requests write-through semantics.
func SyncDirectory(path string) error {
	return syncDirectory(path)
}
