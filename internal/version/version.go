package version

import (
	"errors"
	"fmt"
	"runtime/debug"
	"strings"
)

// ValidateReleaseTag accepts exactly a SemVer 2.0.0 version prefixed with v.
// It parses identifiers rather than relying on a permissive workflow regex.
func ValidateReleaseTag(tag string) error {
	if !strings.HasPrefix(tag, "v") {
		return errors.New("release tag must start with v")
	}
	value := strings.TrimPrefix(tag, "v")
	if value == "" {
		return errors.New("release tag has no version")
	}
	versionAndBuild := strings.Split(value, "+")
	if len(versionAndBuild) > 2 {
		return errors.New("release tag has more than one build separator")
	}
	if len(versionAndBuild) == 2 {
		if err := validateIdentifiers(versionAndBuild[1], false); err != nil {
			return fmt.Errorf("invalid build metadata: %w", err)
		}
	}
	coreAndPrerelease := strings.Split(versionAndBuild[0], "-")
	core := coreAndPrerelease[0]
	if len(coreAndPrerelease) > 1 {
		prerelease := strings.Join(coreAndPrerelease[1:], "-")
		if err := validateIdentifiers(prerelease, true); err != nil {
			return fmt.Errorf("invalid prerelease: %w", err)
		}
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return errors.New("release tag core must contain major, minor, and patch")
	}
	for _, part := range parts {
		if err := validateNumericIdentifier(part); err != nil {
			return fmt.Errorf("invalid release tag core: %w", err)
		}
	}
	return nil
}

func validateIdentifiers(value string, rejectNumericLeadingZeros bool) error {
	identifiers := strings.Split(value, ".")
	for _, identifier := range identifiers {
		if identifier == "" {
			return errors.New("identifier must not be empty")
		}
		numeric := true
		for _, character := range identifier {
			if character < '0' || character > '9' {
				numeric = false
			}
			if character >= '0' && character <= '9' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character == '-' {
				continue
			}
			return fmt.Errorf("identifier %q contains a character outside [0-9A-Za-z-]", identifier)
		}
		if rejectNumericLeadingZeros && numeric && len(identifier) > 1 && identifier[0] == '0' {
			return fmt.Errorf("numeric identifier %q has a leading zero", identifier)
		}
	}
	return nil
}

func validateNumericIdentifier(value string) error {
	if value == "" {
		return errors.New("numeric identifier must not be empty")
	}
	if len(value) > 1 && value[0] == '0' {
		return fmt.Errorf("numeric identifier %q has a leading zero", value)
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return fmt.Errorf("numeric identifier %q contains a non-digit", value)
		}
	}
	return nil
}

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

type Build struct {
	Version string
	Commit  string
	Date    string
}

// Current returns structured producer metadata using the same linker and Go
// build-information fallbacks as String.
func Current() Build {
	buildInfo, _ := debug.ReadBuildInfo()
	version, commit, date := resolve(Version, Commit, Date, buildInfo)
	return Build{Version: version, Commit: commit, Date: date}
}

func String() string {
	current := Current()
	return fmt.Sprintf("%s (commit=%s, date=%s)", current.Version, current.Commit, current.Date)
}

func resolve(version, commit, date string, build *debug.BuildInfo) (string, string, string) {
	if build == nil {
		return version, commit, date
	}
	if (version == "" || version == "dev") && build.Main.Version != "" && build.Main.Version != "(devel)" {
		version = build.Main.Version
	}
	for _, setting := range build.Settings {
		switch setting.Key {
		case "vcs.revision":
			if (commit == "" || commit == "unknown") && strings.TrimSpace(setting.Value) != "" {
				commit = setting.Value
			}
		case "vcs.time":
			if (date == "" || date == "unknown") && strings.TrimSpace(setting.Value) != "" {
				date = setting.Value
			}
		}
	}
	return version, commit, date
}
