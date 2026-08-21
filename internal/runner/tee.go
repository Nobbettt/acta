package runner

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"time"
)

// maxTeeLineBytes bounds the in-flight partial line the tee buffers. A stream
// with no newline (or one pathologically long line) is discarded from live
// parsing rather than growing memory without limit. The raw file still
// keeps full fidelity, and the runner fails visibly via lineErr instead of
// silently producing a live digest that disagrees with `acta digest`.
var maxTeeLineBytes = 16 << 20 // 16 MiB

// lineTee observes the agent's raw stdout as it streams: it stamps each
// completed line's arrival time into the event-times.jsonl sidecar (raw agent
// streams carry no timestamps — arrival time is the only real timing), and
// optionally hands the line to a callback (live OTLP span mapping).
//
// It sits on the recording path, so Write never returns an error; a sidecar
// write failure is recorded in writeErr for the runner to surface after the run.
type lineTee struct {
	sidecar  io.Writer                       // may be nil
	onLine   func(line []byte, at time.Time) // may be nil; line valid only during the call
	buf      bytes.Buffer
	scanned  int // bytes of buf already searched for '\n' (avoids O(n^2) rescan)
	n        int
	scratch  []byte
	writeErr error // first sidecar write error, sticky
	lineErr  error // first over-limit raw line error, sticky
	dropping bool  // currently discarding an over-limit raw line until '\n'
}

func (t *lineTee) Write(p []byte) (int, error) {
	written := len(p)
	for t.dropping {
		idx := bytes.IndexByte(p, '\n')
		if idx < 0 {
			return written, nil
		}
		t.n++ // keep later sidecar line numbers aligned with the raw stream
		t.dropping = false
		p = p[idx+1:]
		if len(p) == 0 {
			return written, nil
		}
	}

	t.buf.Write(p)
	for {
		raw := t.buf.Bytes()
		rel := bytes.IndexByte(raw[t.scanned:], '\n')
		if rel < 0 {
			t.scanned = len(raw)
			if t.scanned >= maxTeeLineBytes {
				t.dropLongLine()
			}
			break
		}
		idx := t.scanned + rel
		if idx >= maxTeeLineBytes {
			t.markLongLine()
			t.buf.Next(idx + 1)
			t.scanned = 0
			t.n++ // newline completed the discarded raw line
			continue
		}
		line := t.buf.Next(idx + 1)
		t.scanned = 0
		t.emit(line[:idx])
	}
	return written, nil
}

func (t *lineTee) Flush() {
	if t.dropping {
		t.n++ // final over-limit unterminated raw line
		t.dropping = false
		return
	}
	if t.buf.Len() == 0 {
		return
	}
	t.emit(t.buf.Next(t.buf.Len()))
	t.scanned = 0
}

func (t *lineTee) dropLongLine() {
	t.markLongLine()
	t.buf.Reset()
	t.scanned = 0
	t.dropping = true
}

func (t *lineTee) markLongLine() {
	if t.lineErr == nil {
		t.lineErr = fmt.Errorf("raw stdout line exceeded %d bytes; live digest skipped that line", maxTeeLineBytes)
	}
}

func (t *lineTee) emit(line []byte) {
	t.n++
	at := time.Now().UTC()
	if t.sidecar != nil {
		t.scratch = append(t.scratch[:0], `{"line":`...)
		t.scratch = strconv.AppendInt(t.scratch, int64(t.n), 10)
		t.scratch = append(t.scratch, `,"t":"`...)
		t.scratch = at.AppendFormat(t.scratch, time.RFC3339Nano)
		t.scratch = append(t.scratch, "\"}\n"...)
		if _, err := t.sidecar.Write(t.scratch); err != nil && t.writeErr == nil {
			t.writeErr = err
		}
	}
	if t.onLine != nil {
		t.onLine(line, at)
	}
}
