package securefile

import (
	"errors"
	"fmt"
)

func replaceFileWithFallback(
	source string,
	target string,
	primary func(string, string) error,
	fallback func(string, string) error,
	shouldFallback func(error) bool,
) error {
	primaryErr := primary(source, target)
	if primaryErr == nil || !shouldFallback(primaryErr) {
		return primaryErr
	}
	if fallbackErr := fallback(source, target); fallbackErr != nil {
		return errors.Join(
			fmt.Errorf("primary atomic replace: %w", primaryErr),
			fmt.Errorf("open-target atomic replace: %w", fallbackErr),
		)
	}
	return nil
}
