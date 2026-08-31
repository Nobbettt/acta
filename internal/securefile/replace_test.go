package securefile

import (
	"errors"
	"testing"
)

func TestReplaceFileWithFallback(t *testing.T) {
	primaryFailure := errors.New("primary failure")
	fallbackFailure := errors.New("fallback failure")

	tests := []struct {
		name             string
		primaryErr       error
		eligible         bool
		fallbackErr      error
		wantFallbackCall bool
		wantPrimaryErr   bool
		wantFallbackErr  bool
	}{
		{name: "primary success"},
		{name: "eligible failure recovers", primaryErr: primaryFailure, eligible: true, wantFallbackCall: true},
		{name: "ineligible failure is returned", primaryErr: primaryFailure, wantPrimaryErr: true},
		{
			name: "fallback failure preserves both causes", primaryErr: primaryFailure, eligible: true,
			fallbackErr: fallbackFailure, wantFallbackCall: true, wantPrimaryErr: true, wantFallbackErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fallbackCalled := false
			err := replaceFileWithFallback(
				"source",
				"target",
				func(source, target string) error {
					if source != "source" || target != "target" {
						t.Fatalf("primary paths = %q, %q", source, target)
					}
					return test.primaryErr
				},
				func(source, target string) error {
					fallbackCalled = true
					if source != "source" || target != "target" {
						t.Fatalf("fallback paths = %q, %q", source, target)
					}
					return test.fallbackErr
				},
				func(err error) bool { return test.eligible && errors.Is(err, primaryFailure) },
			)
			if fallbackCalled != test.wantFallbackCall {
				t.Fatalf("fallback called = %v, want %v", fallbackCalled, test.wantFallbackCall)
			}
			if errors.Is(err, primaryFailure) != test.wantPrimaryErr {
				t.Fatalf("primary error preserved = %v, want %v; error = %v", errors.Is(err, primaryFailure), test.wantPrimaryErr, err)
			}
			if errors.Is(err, fallbackFailure) != test.wantFallbackErr {
				t.Fatalf("fallback error preserved = %v, want %v; error = %v", errors.Is(err, fallbackFailure), test.wantFallbackErr, err)
			}
		})
	}
}
