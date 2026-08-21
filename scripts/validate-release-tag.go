//go:build ignore

package main

import (
	"fmt"
	"os"

	"github.com/nobbettt/acta/internal/version"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./scripts/validate-release-tag.go vMAJOR.MINOR.PATCH")
		os.Exit(2)
	}
	if err := version.ValidateReleaseTag(os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "invalid release tag %q: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}
