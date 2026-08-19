package version

import (
	"runtime/debug"
	"testing"
)

func TestResolveUsesModuleAndVCSBuildInfoAsFallback(t *testing.T) {
	build := &debug.BuildInfo{
		Main: debug.Module{Version: "v0.1.0"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "abcdef123456"},
			{Key: "vcs.time", Value: "2026-08-18T10:00:00Z"},
		},
	}
	version, commit, date := resolve("dev", "unknown", "unknown", build)
	if version != "v0.1.0" || commit != "abcdef123456" || date != "2026-08-18T10:00:00Z" {
		t.Fatalf("resolve() = %q, %q, %q", version, commit, date)
	}
}

func TestResolveKeepsLinkerValues(t *testing.T) {
	build := &debug.BuildInfo{
		Main: debug.Module{Version: "v9.9.9"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "other"},
			{Key: "vcs.time", Value: "2099-01-01T00:00:00Z"},
		},
	}
	version, commit, date := resolve("v1.2.3", "release-commit", "release-date", build)
	if version != "v1.2.3" || commit != "release-commit" || date != "release-date" {
		t.Fatalf("resolve() overwrote linker values: %q, %q, %q", version, commit, date)
	}
}

func TestResolveIgnoresDevelopmentModuleVersion(t *testing.T) {
	version, commit, date := resolve("dev", "unknown", "unknown", &debug.BuildInfo{
		Main: debug.Module{Version: "(devel)"},
	})
	if version != "dev" || commit != "unknown" || date != "unknown" {
		t.Fatalf("resolve() = %q, %q, %q", version, commit, date)
	}
}

func TestValidateReleaseTag(t *testing.T) {
	valid := []string{
		"v0.1.0",
		"v1.2.3-rc.1",
		"v1.2.3-alpha-beta",
		"v1.2.3+build.001",
		"v1.2.3-rc.1+build.7",
	}
	for _, tag := range valid {
		if err := ValidateReleaseTag(tag); err != nil {
			t.Errorf("ValidateReleaseTag(%q) = %v", tag, err)
		}
	}
	invalid := []string{
		"1.2.3", "v", "v1", "v1.2", "v1.2.3.4", "v01.2.3",
		"v1.02.3", "v1.2.03", "v1.2.3-", "v1.2.3-01", "v1.2.3-rc..1",
		"v1.2.3+", "v1.2.3+build..1", "v1.2.3+build+again", "v1.2.3_rc",
	}
	for _, tag := range invalid {
		if err := ValidateReleaseTag(tag); err == nil {
			t.Errorf("ValidateReleaseTag(%q) unexpectedly succeeded", tag)
		}
	}
}
