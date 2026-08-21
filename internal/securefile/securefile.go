// Package securefile creates sensitive run artifacts with owner-only access.
package securefile

import (
	"errors"
	"os"
	"path/filepath"
)

const Mode os.FileMode = 0o600

type AtomicWriter struct {
	file      *os.File
	temporary string
	target    string
	committed bool
}

// Create starts an atomic rewrite beside path. Commit replaces path without
// following it when path is a symlink; Abort leaves the previous path intact.
func Create(path string) (*AtomicWriter, error) {
	dir := filepath.Dir(path)
	file, err := createPrivateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return nil, err
	}
	return &AtomicWriter{file: file, temporary: file.Name(), target: path}, nil
}

func CreateExclusive(path string) (*os.File, error) {
	return createPrivateExclusive(path)
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
	if err := replaceFile(writer.temporary, writer.target); err != nil {
		_ = os.Remove(writer.temporary)
		return err
	}
	writer.committed = true
	return SyncDirectory(filepath.Dir(writer.target))
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

// SyncDirectory makes a successful atomic replacement durable at the
// directory-entry level on platforms which require an explicit directory
// fsync. Windows replaceFile already requests write-through semantics.
func SyncDirectory(path string) error {
	return syncDirectory(path)
}
