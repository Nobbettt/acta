package agents

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var semanticVersionPattern = regexp.MustCompile(`(?:^|[^0-9])([0-9]+)\.([0-9]+)\.([0-9]+)([-+][0-9A-Za-z.-]+)?(?:\s|$)`)

type RunRequest struct {
	CWD                  string
	Prompt               string
	Model                string
	WritableDirs         []string
	CodexSandbox         string
	ClaudePermissionMode string
	ExtraArgs            []string
}

type CommandSpec struct {
	Path           string
	Args           []string
	Dir            string
	Stdin          string
	StdoutFilename string
	StderrFilename string
}

func (s CommandSpec) CommandForRecord() []string {
	return append([]string{s.Path}, s.Args...)
}

type Adapter interface {
	Name() string
	// Provider is the GenAI provider name for trace attributes (e.g. "openai").
	// On the interface so a new agent must declare it, rather than being added
	// to a separate name-keyed switch that can silently drift.
	Provider() string
	DefaultConfigMode() string
	VersionPolicy() VersionPolicy
	BuildCommand(req RunRequest) (CommandSpec, error)
}

// VersionPolicy is the adapter's executable compatibility contract. The
// minimum is intentionally conservative: it is the compatibility floor for
// the flags used by this adapter and is covered by adapter policy tests.
type VersionPolicy struct {
	Args                    []string
	MinimumVersion          string
	MaximumVersionExclusive string
}

// ParseAndValidate extracts the first numeric SemVer core from normal CLI
// version output and rejects a version older than the adapter contract. The
// normalized version is suitable for run provenance records.
func (p VersionPolicy) ParseAndValidate(output string) (string, error) {
	matches := semanticVersionPattern.FindStringSubmatch(strings.TrimSpace(output))
	if len(matches) != 5 {
		return "", fmt.Errorf("version output does not contain a MAJOR.MINOR.PATCH version")
	}
	if strings.HasPrefix(matches[4], "-") {
		return "", fmt.Errorf("prerelease CLI versions are unsupported: %s.%s.%s%s", matches[1], matches[2], matches[3], matches[4])
	}
	actual := [3]uint64{}
	for index := range actual {
		value, err := strconv.ParseUint(matches[index+1], 10, 64)
		if err != nil {
			return "", fmt.Errorf("parse CLI version component: %w", err)
		}
		actual[index] = value
	}
	minimum, err := parsePolicyVersion(p.MinimumVersion)
	if err != nil {
		return "", fmt.Errorf("invalid adapter minimum version %q", p.MinimumVersion)
	}
	version := strings.Join(matches[1:4], ".")
	if compareVersion(actual, minimum) < 0 {
		return version, fmt.Errorf("CLI version %s is older than Acta's minimum supported version %s", version, p.MinimumVersion)
	}
	if p.MaximumVersionExclusive != "" {
		maximum, err := parsePolicyVersion(p.MaximumVersionExclusive)
		if err != nil {
			return "", fmt.Errorf("invalid adapter maximum version %q", p.MaximumVersionExclusive)
		}
		if compareVersion(actual, maximum) >= 0 {
			return version, fmt.Errorf("CLI version %s is outside Acta's tested range [%s, %s)", version, p.MinimumVersion, p.MaximumVersionExclusive)
		}
	}
	return version, nil
}

func parsePolicyVersion(value string) ([3]uint64, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return [3]uint64{}, fmt.Errorf("version must have three components")
	}
	parsed := [3]uint64{}
	for index, part := range parts {
		number, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return [3]uint64{}, err
		}
		parsed[index] = number
	}
	return parsed, nil
}

func compareVersion(left, right [3]uint64) int {
	for index := range left {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}
	return 0
}

func Get(name string) (Adapter, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "codex":
		return Codex{}, nil
	case "claude", "claude-code":
		return Claude{}, nil
	default:
		return nil, fmt.Errorf("unknown agent %q; expected codex or claude", name)
	}
}

// All returns every built-in agent adapter. Consistency tests enumerate this so
// a newly added agent that forgets a digest parser, trace mapper, or provider
// fails loudly instead of degrading silently at runtime.
func All() []Adapter {
	return []Adapter{Codex{}, Claude{}}
}
