package runner

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nobbettt/acta/internal/securefile"
)

// redactReasoningRawStream atomically rewrites a provider JSONL stream so
// objects identified as reasoning/thinking retain structural identity only.
// Invalid non-empty JSON fails closed: redact mode must never publish bytes it
// could not classify.
func redactReasoningRawStream(path string, maxLineBytes int) error {
	if maxLineBytes <= 0 {
		return fmt.Errorf("maximum redaction line size must be positive")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("raw stream must be a regular file")
	}
	input, err := os.Open(path)
	if err != nil {
		return err
	}
	writer, err := securefile.Create(path)
	if err != nil {
		_ = input.Close()
		return err
	}
	defer writer.Abort()

	reader := bufio.NewReaderSize(input, 64<<10)
	lineNumber := 0
	for {
		lineNumber++
		line, readErr := readBoundedReasoningLine(reader, maxLineBytes)
		if readErr == errReasoningLineTooLong {
			_ = input.Close()
			return fmt.Errorf("JSONL line %d exceeds maximum reasoning-redaction line size of %d bytes", lineNumber, maxLineBytes)
		}
		if len(line) > 0 {
			redacted, redactErr := redactReasoningLine(line)
			if redactErr != nil {
				_ = input.Close()
				return redactErr
			}
			if _, err := writer.Write(redacted); err != nil {
				_ = input.Close()
				return err
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				_ = input.Close()
				return readErr
			}
			break
		}
	}
	if err := input.Close(); err != nil {
		return err
	}
	return writer.Commit()
}

var errReasoningLineTooLong = errors.New("reasoning-redaction line too long")

func readBoundedReasoningLine(reader *bufio.Reader, maxLineBytes int) ([]byte, error) {
	line := make([]byte, 0, min(maxLineBytes, 64<<10))
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(fragment) > maxLineBytes-len(line) {
			return nil, errReasoningLineTooLong
		}
		line = append(line, fragment...)
		if err == bufio.ErrBufferFull {
			continue
		}
		return line, err
	}
}

func redactReasoningLine(line []byte) ([]byte, error) {
	hasNewline := len(line) > 0 && line[len(line)-1] == '\n'
	payload := bytes.TrimSpace(line)
	if len(payload) == 0 {
		return line, nil
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("parse raw provider event for reasoning redaction: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("multiple JSON values")
		}
		return nil, fmt.Errorf("parse raw provider event for reasoning redaction: %w", err)
	}
	if !redactReasoningValue(value) {
		return line, nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode reasoning-redacted provider event: %w", err)
	}
	if hasNewline {
		encoded = append(encoded, '\n')
	}
	return encoded, nil
}

func redactReasoningValue(value any) bool {
	switch typed := value.(type) {
	case []any:
		changed := false
		for _, item := range typed {
			changed = redactReasoningValue(item) || changed
		}
		return changed
	case map[string]any:
		kind, _ := typed["type"].(string)
		kind = strings.ToLower(strings.TrimSpace(kind))
		if strings.Contains(kind, "reasoning") || strings.Contains(kind, "thinking") {
			for key := range typed {
				switch key {
				case "type", "id", "status":
				default:
					delete(typed, key)
				}
			}
			return true
		}
		changed := false
		for _, item := range typed {
			changed = redactReasoningValue(item) || changed
		}
		return changed
	default:
		return false
	}
}
