package reporting

import (
	"errors"
	"os"
)

type projectionProbeCreate func(string, string) (*os.File, error)

func probeProjectionDirectoryWritable(path string, create projectionProbeCreate, remove func(string) error, readOnlyError func(error) bool) (bool, error) {
	file, err := create(path, ".acta-write-probe-*")
	if err != nil {
		if readOnlyError(err) {
			return false, nil
		}
		return false, err
	}
	name := file.Name()
	if err := errors.Join(file.Close(), remove(name)); err != nil {
		return false, err
	}
	return true, nil
}
