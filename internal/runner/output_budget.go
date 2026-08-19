package runner

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
)

var errRawOutputLimit = errors.New("raw output byte limit exceeded")

// rawOutputBudget coordinates stdout and stderr against one combined limit.
// Writers return the limit error to the subprocess pipe and cancel its process
// context; a run can therefore never report success after output was omitted.
type rawOutputBudget struct {
	mu        sync.Mutex
	remaining int64
	limit     int64
	exceeded  bool
	cancel    func()
}

func newRawOutputBudget(limit int64, cancel func()) *rawOutputBudget {
	return &rawOutputBudget{remaining: limit, limit: limit, cancel: cancel}
}

func (b *rawOutputBudget) writer(destination io.Writer) io.Writer {
	if b == nil || b.limit == 0 {
		return destination
	}
	return &budgetedWriter{budget: b, destination: destination}
}

func (b *rawOutputBudget) Err() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.exceeded {
		return nil
	}
	return fmt.Errorf("%w (combined stdout/stderr limit %d bytes)", errRawOutputLimit, b.limit)
}

type budgetedWriter struct {
	budget      *rawOutputBudget
	destination io.Writer
}

type boundedCapture struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	maxBytes int
	overflow bool
}

func (w *boundedCapture) Write(payload []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	remaining := w.maxBytes - w.buffer.Len()
	if remaining > 0 {
		keep := len(payload)
		if keep > remaining {
			keep = remaining
		}
		_, _ = w.buffer.Write(payload[:keep])
	}
	if len(payload) > remaining {
		w.overflow = true
	}
	// Consume excess output so the version process gets a clear parse/size
	// failure instead of an incidental broken pipe.
	return len(payload), nil
}

func (w *boundedCapture) result() (string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buffer.String(), w.overflow
}

func (w *budgetedWriter) Write(payload []byte) (int, error) {
	b := w.budget
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.exceeded || b.remaining == 0 {
		b.exceeded = true
		if b.cancel != nil {
			b.cancel()
		}
		return 0, errRawOutputLimit
	}
	allowed := int64(len(payload))
	if allowed > b.remaining {
		allowed = b.remaining
	}
	written, err := w.destination.Write(payload[:allowed])
	b.remaining -= int64(written)
	if err != nil {
		return written, err
	}
	if int64(len(payload)) > allowed {
		b.exceeded = true
		if b.cancel != nil {
			b.cancel()
		}
		return written, errRawOutputLimit
	}
	return written, nil
}
