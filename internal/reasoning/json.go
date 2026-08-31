package reasoning

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// ValidateUniqueObjectKeys verifies that payload is one complete JSON value
// and rejects duplicate keys at any object depth. Redaction callers must run
// this token scan before decoding into maps, because encoding/json otherwise
// silently applies last-key-wins semantics.
func ValidateUniqueObjectKeys(payload []byte) error {
	return ValidateUniqueObjectKeysContext(context.Background(), payload)
}

// UnmarshalProviderLine is the single decode boundary for raw provider lines.
// It rejects duplicate object keys at any depth before decoding can apply
// encoding/json's last-key-wins behavior.
func UnmarshalProviderLine(payload []byte, value any) error {
	if err := ValidateUniqueObjectKeys(payload); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	return decoder.Decode(value)
}

// ValidateUniqueObjectKeysContext is ValidateUniqueObjectKeys with
// cancellation checks while scanning potentially large artifacts.
func ValidateUniqueObjectKeysContext(ctx context.Context, payload []byte) error {
	decoder := json.NewDecoder(jsonContextReader{ctx: ctx, reader: bytes.NewReader(payload)})
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

type jsonContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r jsonContextReader) Read(payload []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(payload)
}
