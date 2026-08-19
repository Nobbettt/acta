package runtimebundle

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPrepareMaterializesCodexCapabilitiesAndCleansSkills(t *testing.T) {
	cwd := t.TempDir()
	bundlePath := filepath.Join(t.TempDir(), "runtime-bundle.json")
	bundle := Bundle{
		SchemaVersion: 1, Adapter: "codex", Model: "gpt-test",
		Capabilities: []Capability{
			{ID: "docs", Name: "Docs MCP", Description: "Documentation tools.", Kind: "mcp", Configuration: map[string]any{
				"server_slug": "docs", "url": "https://mcp.example.com/mcp", "enabled_tools": []string{"search"}, "required": true,
			}},
			{ID: "web-search", Name: "Web search", Description: "Live web search.", Kind: "tool", Configuration: map[string]any{"config_key": "web_search", "value": "live"}},
			{ID: "review-guide", Name: "Review guide", Description: "Review instructions.", Kind: "skill", Configuration: map[string]any{
				"name": "review-guide", "description": "Review changes safely.", "instructions": "Inspect the diff and report correctness risks.",
			}},
		},
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePrivateBundle(bundlePath, encoded); err != nil {
		t.Fatal(err)
	}
	prepared, err := Prepare(bundlePath, cwd, "codex", "")
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if prepared.Model != "gpt-test" {
		t.Fatalf("model = %q", prepared.Model)
	}
	if prepared.ConfigMode != "authoritative_bundle" {
		t.Fatalf("config mode = %q", prepared.ConfigMode)
	}
	wantHash := fmt.Sprintf("%x", sha256.Sum256(encoded))
	if prepared.BundleSHA256 != wantHash {
		t.Fatalf("bundle SHA-256 = %q, want %q", prepared.BundleSHA256, wantHash)
	}
	joined := strings.Join(prepared.AgentArgs, " ")
	for _, fragment := range []string{"--ignore-user-config", "--ignore-rules", "--strict-config", "mcp_servers={}", "mcp_servers.docs.url", "mcp_servers.docs.enabled_tools", "web_search=\"disabled\"", "web_search=\"live\"", "skills.config"} {
		if !strings.Contains(joined, fragment) {
			t.Errorf("agent args %q do not contain %q", joined, fragment)
		}
	}
	skillPath := filepath.Join(cwd, "managed-skills", "skill-review-guide", "SKILL.md")
	if _, err := os.Stat(skillPath); err != nil {
		t.Fatalf("managed skill was not materialized: %v", err)
	}
	if err := prepared.Cleanup(); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if _, err := os.Stat(skillPath); !os.IsNotExist(err) {
		t.Fatalf("managed skill still exists after cleanup: %v", err)
	}
}

func TestPrepareRejectsSymlinkedManagedSkillRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires additional Windows privileges")
	}
	controlRoot := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(controlRoot, "managed-skills")); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(t.TempDir(), "runtime-bundle.json")
	bundle := Bundle{
		SchemaVersion: 1,
		Adapter:       "codex",
		Model:         "gpt-test",
		Capabilities: []Capability{{
			ID: "review-guide", Name: "Review guide", Description: "Review instructions.", Kind: "skill", Configuration: map[string]any{
				"description": "Review changes safely.", "instructions": "Inspect the diff.",
			},
		}},
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePrivateBundle(bundlePath, encoded); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(bundlePath, controlRoot, "codex", ""); err == nil || !strings.Contains(err.Error(), "real directory") {
		t.Fatalf("Prepare() symlinked skill root error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "skill-review-guide")); !os.IsNotExist(err) {
		t.Fatalf("managed skill escaped through symlink: %v", err)
	}
}

func TestPrepareRejectsPublicOrConflictingBundle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.json")
	payload := []byte(`{"schema_version":1,"adapter":"codex","model":"one","capabilities":[]}`)
	if err := writePrivateBundle(path, payload); err != nil {
		t.Fatal(err)
	}
	if err := makeBundlePublic(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(path, t.TempDir(), "codex", "two"); err == nil || !strings.Contains(err.Error(), "private regular file") {
		t.Fatalf("public bundle error = %v", err)
	}
	if err := makeBundlePrivate(path, payload); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(path, t.TempDir(), "codex", "two"); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("conflicting model error = %v", err)
	}
}

func TestPrepareRejectsEmbeddedSecretValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.json")
	bundle := Bundle{
		SchemaVersion: 1,
		Adapter:       "codex",
		Model:         "gpt-test",
		Capabilities: []Capability{{
			ID: "docs", Name: "Docs MCP", Description: "Documentation tools.", Kind: "mcp",
			Configuration: map[string]any{
				"url":     "https://mcp.example.com/mcp",
				"headers": map[string]any{"authorization": "Bearer should-never-be-here"},
			},
		}},
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePrivateBundle(path, encoded); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(path, t.TempDir(), "codex", ""); err == nil || !strings.Contains(err.Error(), "forbidden secret field") {
		t.Fatalf("embedded secret error = %v", err)
	}
}

func TestMCPArgsRejectURLQueryAndFragment(t *testing.T) {
	for _, rawURL := range []string{
		"https://mcp.example.com/mcp?token=secret",
		"https://mcp.example.com/mcp#credential",
	} {
		_, err := mcpArgs(Capability{
			ID: "docs", Name: "Docs", Description: "Documentation tools.", Kind: "mcp",
			Configuration: map[string]any{"url": rawURL},
		})
		if err == nil || !strings.Contains(err.Error(), "query or fragment") {
			t.Fatalf("mcpArgs(%q) error = %v", rawURL, err)
		}
	}
}

func TestPrepareRejectsAmbiguousEffectiveConfiguration(t *testing.T) {
	tests := []struct {
		name         string
		capabilities []Capability
		wantError    string
	}{
		{
			name: "duplicate effective tool key",
			capabilities: []Capability{
				toolCapability("web-one", "web_search", "cached"),
				toolCapability("web-two", "web_search", "live"),
			},
			wantError: "duplicate effective config_key",
		},
		{
			name: "duplicate effective server slug",
			capabilities: []Capability{
				mcpCapability("docs-one", "docs", []string{"search"}, nil),
				mcpCapability("docs-two", "docs", []string{"read"}, nil),
			},
			wantError: "duplicate effective server_slug",
		},
		{
			name: "tool enabled and disabled",
			capabilities: []Capability{
				mcpCapability("docs", "docs", []string{"search"}, []string{"search"}),
			},
			wantError: "both enabled and disabled",
		},
		{
			name: "duplicate tool list entry",
			capabilities: []Capability{
				mcpCapability("docs", "docs", []string{"search", "search"}, nil),
			},
			wantError: "duplicate entry",
		},
		{
			name: "blank tool list entry",
			capabilities: []Capability{
				mcpCapability("docs", "docs", []string{""}, nil),
			},
			wantError: "non-blank",
		},
		{
			name:         "blank explicit server slug",
			capabilities: []Capability{mcpCapability("docs", "", nil, nil)},
			wantError:    "server_slug must not be blank",
		},
		{
			name: "blank explicit bearer environment",
			capabilities: []Capability{{
				ID: "docs", Name: "Docs", Description: "Docs", Kind: "mcp",
				Configuration: map[string]any{"url": "https://mcp.example.com/mcp", "bearer_token_env_var": " "},
			}},
			wantError: "canonical and non-blank",
		},
		{
			name: "padded URL",
			capabilities: []Capability{{
				ID: "docs", Name: "Docs", Description: "Docs", Kind: "mcp",
				Configuration: map[string]any{"url": " https://mcp.example.com/mcp"},
			}},
			wantError: "canonical non-blank url",
		},
		{
			name: "blank explicit skill name",
			capabilities: []Capability{{
				ID: "review", Name: "Review", Description: "Review", Kind: "skill",
				Configuration: map[string]any{"name": " ", "description": "Review", "instructions": "Review."},
			}},
			wantError: "name must not be blank",
		},
		{
			name: "null optional MCP field",
			capabilities: []Capability{{
				ID: "docs", Name: "Docs", Description: "Docs", Kind: "mcp",
				Configuration: map[string]any{"url": "https://mcp.example.com/mcp", "required": nil},
			}},
			wantError: "must not be null",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := prepareTestBundle(t, Bundle{SchemaVersion: 1, Adapter: "codex", Capabilities: test.capabilities})
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Prepare() error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestPrepareEnforcesTypedToolConfiguration(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		value     any
		wantError string
	}{
		{name: "web search boolean", key: "web_search", value: true, wantError: "disabled, cached, or live"},
		{name: "web search unknown enum", key: "web_search", value: "sometimes", wantError: "disabled, cached, or live"},
		{name: "multi agent string", key: "features.multi_agent", value: "true", wantError: "must be a boolean"},
		{name: "image generation integer", key: "features.image_generation", value: json.Number("9007199254740993"), wantError: "must be a boolean"},
		{name: "blank key", key: "", value: true, wantError: "config_key"},
		{name: "padded key", key: " features.multi_agent", value: true, wantError: "canonical config_key"},
		{name: "unsupported key", key: "features.unknown", value: true, wantError: "unsupported Codex config key"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := prepareTestBundle(t, Bundle{
				SchemaVersion: 1,
				Adapter:       "codex",
				Capabilities:  []Capability{toolCapability("typed-tool", test.key, test.value)},
			})
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Prepare() error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestPrepareRequiresCanonicalCapabilityMetadata(t *testing.T) {
	tests := []Capability{
		{ID: "Bad_ID", Name: "Tool", Description: "Description", Kind: "tool", Configuration: map[string]any{"config_key": "web_search", "value": "live"}},
		{ID: "tool", Name: "", Description: "Description", Kind: "tool", Configuration: map[string]any{"config_key": "web_search", "value": "live"}},
		{ID: "tool", Name: "Tool", Description: "", Kind: "tool", Configuration: map[string]any{"config_key": "web_search", "value": "live"}},
	}
	for index, capability := range tests {
		if _, err := prepareTestBundle(t, Bundle{SchemaVersion: 1, Adapter: "codex", Capabilities: []Capability{capability}}); err == nil {
			t.Fatalf("case %d: Prepare() unexpectedly succeeded", index)
		}
	}
}

func TestPrepareRequiresResolvedModel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := writePrivateBundle(path, []byte(`{"schema_version":1,"adapter":"codex","capabilities":[]}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(path, t.TempDir(), "codex", ""); err == nil || !strings.Contains(err.Error(), "requires a model") {
		t.Fatalf("missing model error = %v", err)
	}
	prepared, err := Prepare(path, t.TempDir(), "codex", "gpt-explicit")
	if err != nil || prepared.Model != "gpt-explicit" {
		t.Fatalf("explicit model = %q, %v", prepared.Model, err)
	}
}

func TestPrepareRejectsNullContractFields(t *testing.T) {
	for _, payload := range []string{
		`{"schema_version":1,"adapter":"codex","model":"gpt-test","capabilities":null}`,
		`{"schema_version":1,"adapter":"codex","model":null,"capabilities":[]}`,
	} {
		path := filepath.Join(t.TempDir(), "bundle.json")
		if err := writePrivateBundle(path, []byte(payload)); err != nil {
			t.Fatal(err)
		}
		if _, err := Prepare(path, t.TempDir(), "codex", "gpt-explicit"); err == nil {
			t.Fatalf("Prepare(%s) unexpectedly succeeded", payload)
		}
	}
}

func TestPrepareBoundsCapabilitiesAndResolvedArguments(t *testing.T) {
	tooMany := make([]Capability, maxCapabilities+1)
	for index := range tooMany {
		tooMany[index] = Capability{
			ID: fmt.Sprintf("skill-%d", index), Name: "Skill", Description: "Description", Kind: "skill",
			Configuration: map[string]any{"description": "Description", "instructions": "Instructions"},
		}
	}
	if _, err := prepareTestBundle(t, Bundle{SchemaVersion: 1, Adapter: "codex", Capabilities: tooMany}); err == nil || !strings.Contains(err.Error(), "maximum is") {
		t.Fatalf("capability count error = %v", err)
	}

	longToolName := strings.Repeat("x", maxResolvedArgsBytes)
	capability := mcpCapability("docs", "docs", []string{longToolName}, nil)
	if _, err := prepareTestBundle(t, Bundle{SchemaVersion: 1, Adapter: "codex", Capabilities: []Capability{capability}}); err == nil || !strings.Contains(err.Error(), "resolved runtime arguments") {
		t.Fatalf("argument size error = %v", err)
	}
}

func TestPublishedRuntimeBundleExampleIsExecutable(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "..", "schemas", "examples", "runtime-bundle.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "runtime-bundle.json")
	if err := writePrivateBundle(path, payload); err != nil {
		t.Fatal(err)
	}
	prepared, err := Prepare(path, t.TempDir(), "codex", "")
	if err != nil {
		t.Fatalf("published runtime bundle example: %v", err)
	}
	if err := prepared.Cleanup(); err != nil {
		t.Fatal(err)
	}
}

func toolCapability(id, key string, value any) Capability {
	return Capability{
		ID: id, Name: id, Description: "A typed Codex tool.", Kind: "tool",
		Configuration: map[string]any{"config_key": key, "value": value},
	}
}

func mcpCapability(id, slug string, enabled, disabled []string) Capability {
	configuration := map[string]any{
		"server_slug": slug, "url": "https://mcp.example.com/mcp",
	}
	if enabled != nil {
		configuration["enabled_tools"] = enabled
	}
	if disabled != nil {
		configuration["disabled_tools"] = disabled
	}
	return Capability{
		ID: id, Name: id, Description: "An MCP server.", Kind: "mcp",
		Configuration: configuration,
	}
}

func prepareTestBundle(t *testing.T, bundle Bundle) (Prepared, error) {
	t.Helper()
	if bundle.Model == "" {
		bundle.Model = "gpt-test"
	}
	path := filepath.Join(t.TempDir(), "runtime-bundle.json")
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePrivateBundle(path, encoded); err != nil {
		t.Fatal(err)
	}
	return Prepare(path, t.TempDir(), "codex", "")
}
