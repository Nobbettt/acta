// Package contextio adds context cancellation checks to I/O operations.
package contextio

import (
	"context"
	"io"
)

type Reader struct {
	context.Context
	io.Reader
}

func (r Reader) Read(payload []byte) (int, error) {
	if err := r.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(payload)
}

type Writer struct {
	context.Context
	io.Writer
}

func (w Writer) Write(payload []byte) (int, error) {
	if err := w.Err(); err != nil {
		return 0, err
	}
	return w.Writer.Write(payload)
}
