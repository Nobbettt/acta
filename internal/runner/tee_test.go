package runner

import (
	"strings"
	"testing"
	"time"
)

func TestLineTeeChunkedWrites(t *testing.T) {
	var sidecar strings.Builder
	var lines []string
	tee := &lineTee{
		sidecar: &sidecar,
		onLine: func(line []byte, at time.Time) {
			lines = append(lines, string(line))
		},
	}

	// Two lines split across three writes, mid-line, plus a trailing partial
	// line that is finalized by Flush after the subprocess exits.
	input := "{\"a\":1}\n{\"b\":2}\npartial"
	for _, chunk := range []string{input[:3], input[3:10], input[10:]} {
		n, err := tee.Write([]byte(chunk))
		if err != nil || n != len(chunk) {
			t.Fatalf("Write = %d,%v want %d,nil", n, err, len(chunk))
		}
	}

	if len(lines) != 2 || lines[0] != `{"a":1}` || lines[1] != `{"b":2}` {
		t.Errorf("lines = %#v, want the two complete JSON lines", lines)
	}
	sc := sidecar.String()
	if !strings.Contains(sc, `{"line":1,`) || !strings.Contains(sc, `{"line":2,`) {
		t.Errorf("sidecar missing line stamps:\n%s", sc)
	}
	if strings.Contains(sc, `{"line":3,`) {
		t.Errorf("partial line must not be stamped before Flush:\n%s", sc)
	}

	tee.Flush()
	if len(lines) != 3 || lines[2] != "partial" {
		t.Errorf("lines after Flush = %#v, want trailing partial emitted once", lines)
	}
	if !strings.Contains(sidecar.String(), `{"line":3,`) {
		t.Errorf("sidecar missing flushed partial line stamp:\n%s", sidecar.String())
	}
}

// A single line delivered across many chunks is assembled once, and the
// scanned offset prevents repeated scans of the same bytes.
func TestLineTeeSingleLineManyChunks(t *testing.T) {
	var lines []string
	tee := &lineTee{onLine: func(line []byte, at time.Time) { lines = append(lines, string(line)) }}
	for _, c := range []string{"a", "b", "c", "d\n"} {
		if _, err := tee.Write([]byte(c)); err != nil {
			t.Fatal(err)
		}
	}
	if len(lines) != 1 || lines[0] != "abcd" {
		t.Fatalf("lines = %#v, want [abcd]", lines)
	}
}

// A newline-free stream must not grow the buffer without bound: once it exceeds
// the cap it is discarded from live parsing and surfaced via lineErr.
func TestLineTeeBoundsMemory(t *testing.T) {
	orig := maxTeeLineBytes
	maxTeeLineBytes = 1024
	defer func() { maxTeeLineBytes = orig }()

	var emitted int
	tee := &lineTee{onLine: func(line []byte, at time.Time) { emitted++ }}
	// 3x the cap, no newline at all.
	if _, err := tee.Write(make([]byte, maxTeeLineBytes*3)); err != nil {
		t.Fatal(err)
	}
	if emitted != 0 {
		t.Fatalf("over-long partial must not be emitted to live digest, emitted %d chunks", emitted)
	}
	if tee.lineErr == nil {
		t.Fatal("over-long line was not surfaced")
	}
	if tee.buf.Len() >= maxTeeLineBytes {
		t.Fatalf("buffer not bounded: %d bytes still held", tee.buf.Len())
	}
}

func TestLineTeeContinuesAfterOverlongLine(t *testing.T) {
	orig := maxTeeLineBytes
	maxTeeLineBytes = 16
	defer func() { maxTeeLineBytes = orig }()

	var lines []string
	tee := &lineTee{onLine: func(line []byte, at time.Time) { lines = append(lines, string(line)) }}
	if _, err := tee.Write([]byte("01234567890123456789\nok\n")); err != nil {
		t.Fatal(err)
	}
	if tee.lineErr == nil {
		t.Fatal("expected overlong line error")
	}
	if len(lines) != 1 || lines[0] != "ok" {
		t.Fatalf("lines = %#v, want only the valid line after the overlong one", lines)
	}
}
