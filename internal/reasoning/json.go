package reasoning

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/nobbettt/acta/internal/contextio"
)

// ErrInvalidProviderEnvelope reports a complete JSON provider line whose
// top-level value is not an object envelope.
var ErrInvalidProviderEnvelope = errors.New("provider line is not a JSON object envelope")

// ErrProviderLineTooLong reports a provider JSONL record that exceeds its
// caller-supplied byte limit.
var ErrProviderLineTooLong = errors.New("provider line too long")

// ReadBoundedProviderLine reads one provider JSONL record without allowing
// bufio's internal buffer size to become the record-size limit.
func ReadBoundedProviderLine(reader *bufio.Reader, maxLineBytes int) ([]byte, error) {
	line := make([]byte, 0, min(maxLineBytes, 64<<10))
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(fragment) > maxLineBytes-len(line) {
			return nil, ErrProviderLineTooLong
		}
		line = append(line, fragment...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return line, err
	}
}

// ValidateUniqueObjectKeys verifies that payload is one complete JSON value
// and rejects duplicate keys at any object depth. Redaction callers must run
// this token scan before decoding into maps, because encoding/json otherwise
// silently applies last-key-wins semantics.
func ValidateUniqueObjectKeys(payload []byte) error {
	return ValidateUniqueObjectKeysContext(context.Background(), payload)
}

// UnmarshalValue rejects duplicate keys, preserves JSON numbers, and requires
// exactly one complete JSON value.
func UnmarshalValue(payload []byte, value any) error {
	return UnmarshalValueContext(context.Background(), payload, value)
}

// UnmarshalValueContext is UnmarshalValue with cancellation checks while
// scanning and decoding potentially large values.
func UnmarshalValueContext(ctx context.Context, payload []byte, value any) error {
	return unmarshalValueContext(ctx, payload, value, false)
}

// UnmarshalProviderLine is the single decode boundary for raw provider lines.
// In addition to UnmarshalValue's guarantees, it requires an object envelope.
func UnmarshalProviderLine(payload []byte, value any) error {
	return unmarshalValueContext(context.Background(), payload, value, true)
}

func unmarshalValueContext(ctx context.Context, payload []byte, value any, requireObject bool) error {
	if err := ValidateUniqueObjectKeysContext(ctx, payload); err != nil {
		return err
	}
	if trimmed := bytes.TrimSpace(payload); requireObject && (len(trimmed) == 0 || trimmed[0] != '{') {
		return ErrInvalidProviderEnvelope
	}
	decoder := json.NewDecoder(contextio.Reader{Context: ctx, Reader: bytes.NewReader(payload)})
	decoder.UseNumber()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	return ctx.Err()
}

// ValidateUniqueObjectKeysContext is ValidateUniqueObjectKeys with
// cancellation checks while scanning potentially large artifacts.
func ValidateUniqueObjectKeysContext(ctx context.Context, payload []byte) error {
	decoder := json.NewDecoder(contextio.Reader{Context: ctx, Reader: bytes.NewReader(payload)})
	decoder.UseNumber()

	type frame struct {
		delim        json.Delim
		keys         map[string]struct{}
		expectingKey bool
	}
	var stack []frame
	rootValues := 0
	acceptValue := func() error {
		if len(stack) == 0 {
			rootValues++
			if rootValues > 1 {
				return fmt.Errorf("multiple JSON values")
			}
			return nil
		}
		parent := &stack[len(stack)-1]
		if parent.delim == '{' {
			if parent.expectingKey {
				return fmt.Errorf("expected JSON object key")
			}
			parent.expectingKey = true
		}
		return nil
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		token, err := decoder.Token()
		if err == io.EOF {
			if rootValues == 0 {
				return io.EOF
			}
			if len(stack) != 0 {
				return fmt.Errorf("unterminated JSON container")
			}
			return ctx.Err()
		}
		if err != nil {
			return err
		}

		delim, isDelim := token.(json.Delim)
		if isDelim {
			switch delim {
			case '{', '[':
				if err := acceptValue(); err != nil {
					return err
				}
				entry := frame{delim: delim}
				if delim == '{' {
					entry.keys = make(map[string]struct{})
					entry.expectingKey = true
				}
				stack = append(stack, entry)
			case '}', ']':
				if len(stack) == 0 {
					return fmt.Errorf("unexpected JSON delimiter %q", delim)
				}
				entry := stack[len(stack)-1]
				if (entry.delim == '{' && delim != '}') || (entry.delim == '[' && delim != ']') {
					return fmt.Errorf("mismatched JSON delimiter %q", delim)
				}
				if entry.delim == '{' && !entry.expectingKey {
					return fmt.Errorf("missing JSON object value")
				}
				stack = stack[:len(stack)-1]
			}
			continue
		}

		if len(stack) > 0 {
			entry := &stack[len(stack)-1]
			if entry.delim == '{' && entry.expectingKey {
				key, ok := token.(string)
				if !ok {
					return fmt.Errorf("expected JSON object key")
				}
				if _, duplicate := entry.keys[key]; duplicate {
					return fmt.Errorf("duplicate JSON object key %q", key)
				}
				entry.keys[key] = struct{}{}
				entry.expectingKey = false
				continue
			}
		}
		if err := acceptValue(); err != nil {
			return err
		}
	}
}
