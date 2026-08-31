package runner

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/nobbettt/acta/internal/reasoning"
	"github.com/nobbettt/acta/internal/securefile"
)

// redactReasoningRawStream atomically rewrites a provider JSONL stream so
// known Codex and Claude reasoning blocks retain structural identity only.
// Invalid non-empty JSON fails closed: redact mode must never publish bytes it
// could not classify.
func redactReasoningRawStream(path string, maxLineBytes int) (string, error) {
	return redactReasoningRawStreamWithWriter(path, maxLineBytes, func(path string) (reasoningAtomicWriter, error) {
		return securefile.Create(path)
	})
}

type reasoningAtomicWriter interface {
	Write([]byte) (int, error)
	Commit() error
	Abort() error
	TargetReplaced() bool
}

func redactReasoningRawStreamWithWriter(path string, maxLineBytes int, createWriter func(string) (reasoningAtomicWriter, error)) (string, error) {
	if maxLineBytes <= 0 {
		return "failed", fmt.Errorf("maximum redaction line size must be positive")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "failed", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "failed", fmt.Errorf("raw stream must be a regular file")
	}
	input, err := securefile.OpenRegular(filepath.Dir(path), path)
	if err != nil {
		return "failed", err
	}
	originalHash, err := hashReasoningStream(input)
	if err != nil {
		_ = input.Close()
		return "failed", fmt.Errorf("hash original raw stream: %w", err)
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		_ = input.Close()
		return "failed", fmt.Errorf("rewind original raw stream: %w", err)
	}
	writer, err := createWriter(path)
	if err != nil {
		_ = input.Close()
		return "failed", err
	}
	defer writer.Abort()

	reader := bufio.NewReaderSize(input, 64<<10)
	lineNumber := 0
	for {
		lineNumber++
		line, readErr := readBoundedReasoningLine(reader, maxLineBytes)
		if readErr == errReasoningLineTooLong {
			_ = input.Close()
			return "failed", fmt.Errorf("JSONL line %d exceeds maximum reasoning-redaction line size of %d bytes", lineNumber, maxLineBytes)
		}
		if len(line) > 0 {
			redacted, redactErr := redactReasoningLine(line)
			if redactErr != nil {
				_ = input.Close()
				return "failed", redactErr
			}
			if _, err := writer.Write(redacted); err != nil {
				_ = input.Close()
				return "failed", err
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				_ = input.Close()
				return "failed", readErr
			}
			break
		}
	}
	if err := input.Close(); err != nil {
		return "failed", err
	}
	if err := writer.Commit(); err != nil {
		if !writer.TargetReplaced() {
			return "failed", fmt.Errorf("commit redacted raw stream before replacement: %w", err)
		}
		currentHash, verifyErr := hashReasoningFile(path)
		if verifyErr != nil {
			return "partial", errors.Join(fmt.Errorf("commit redacted raw stream after replacement: %w", err), fmt.Errorf("verify original raw stream after ambiguous commit: %w", verifyErr))
		}
		if currentHash == originalHash {
			return "failed", fmt.Errorf("commit redacted raw stream after replacement; original stream hash verified unchanged: %w", err)
		}
		return "partial", fmt.Errorf("commit redacted raw stream after replacement; current stream differs from the original: %w", err)
	}
	return "redacted", nil
}

func hashReasoningFile(path string) ([sha256.Size]byte, error) {
	file, err := securefile.OpenRegular(filepath.Dir(path), path)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer file.Close()
	return hashReasoningStream(file)
}

func hashReasoningStream(reader io.Reader) ([sha256.Size]byte, error) {
	hash := sha256.New()
	if _, err := io.Copy(hash, reader); err != nil {
		return [sha256.Size]byte{}, err
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result, nil
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
	if err := reasoning.ValidateUniqueObjectKeys(payload); err != nil {
		return nil, fmt.Errorf("parse raw provider event for reasoning redaction: %w", err)
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
	changed, verified := reasoning.RedactValue(value, reasoning.ProviderTraversal())
	if !verified {
		return nil, fmt.Errorf("provider event reasoning redaction could not be verified")
	}
	if !changed {
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
