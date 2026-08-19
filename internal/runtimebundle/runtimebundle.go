package runtimebundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/nobbettt/acta/internal/securefile"
)

const (
	maxBundleBytes       = 1 << 20
	maxCapabilities      = 128
	maxResolvedArgsBytes = 256 << 10
)

var authoritativeCodexDefaults = map[string]string{
	"features.image_generation": "false",
	"features.multi_agent":      "false",
	"mcp_servers":               "{}",
	"skills.config":             "[]",
	"web_search":                tomlString("disabled"),
}

var safeIDPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

type Bundle struct {
	SchemaVersion int          `json:"schema_version"`
	Adapter       string       `json:"adapter"`
	Model         string       `json:"model,omitempty"`
	Capabilities  []Capability `json:"capabilities"`
}

type Capability struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Kind          string         `json:"kind"`
	Description   string         `json:"description"`
	Configuration map[string]any `json:"configuration,omitempty"`
}

type Prepared struct {
	Model        string
	AgentArgs    []string
	ConfigMode   string
	BundleSHA256 string
	cleanup      func() error
}

func (p Prepared) Cleanup() error {
	if p.cleanup == nil {
		return nil
	}
	return p.cleanup()
}

func Prepare(path, controlRoot, agent, explicitModel string) (Prepared, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Prepared{Model: strings.TrimSpace(explicitModel)}, nil
	}
	if !filepath.IsAbs(path) {
		return Prepared{}, errors.New("runtime bundle path must be absolute")
	}
	file, err := securefile.OpenRegular(filepath.Dir(path), path)
	if err != nil {
		return Prepared{}, fmt.Errorf("open runtime bundle: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return Prepared{}, fmt.Errorf("stat runtime bundle: %w", err)
	}
	if info.Size() > maxBundleBytes {
		return Prepared{}, errors.New("runtime bundle must be a private regular file no larger than 1 MiB")
	}
	if err := securefile.ValidatePrivate(file); err != nil {
		return Prepared{}, fmt.Errorf("runtime bundle must be a private regular file no larger than 1 MiB: %w", err)
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxBundleBytes+1))
	if err != nil {
		return Prepared{}, fmt.Errorf("read runtime bundle: %w", err)
	}
	if len(payload) > maxBundleBytes {
		return Prepared{}, errors.New("runtime bundle must be no larger than 1 MiB")
	}
	digest := sha256.Sum256(payload)
	var bundle Bundle
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(&bundle); err != nil {
		return Prepared{}, fmt.Errorf("decode runtime bundle: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Prepared{}, errors.New("runtime bundle must contain one JSON object")
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return Prepared{}, fmt.Errorf("decode runtime bundle envelope: %w", err)
	}
	capabilitiesJSON, hasCapabilities := envelope["capabilities"]
	if !hasCapabilities || len(bytes.TrimSpace(capabilitiesJSON)) == 0 || bytes.TrimSpace(capabilitiesJSON)[0] != '[' {
		return Prepared{}, errors.New("runtime bundle capabilities must be an array")
	}
	if modelJSON, explicitlySet := envelope["model"]; explicitlySet {
		if len(bytes.TrimSpace(modelJSON)) == 0 || bytes.TrimSpace(modelJSON)[0] != '"' || strings.TrimSpace(bundle.Model) == "" || strings.TrimSpace(bundle.Model) != bundle.Model {
			return Prepared{}, errors.New("runtime bundle model must be a canonical non-blank string when provided")
		}
	}
	agent = strings.TrimSpace(agent)
	if bundle.SchemaVersion != 1 || bundle.Adapter != "codex" || agent != bundle.Adapter {
		return Prepared{}, errors.New("runtime bundle schema or adapter is unsupported")
	}
	if len(bundle.Capabilities) > maxCapabilities {
		return Prepared{}, fmt.Errorf("runtime bundle has %d capabilities; maximum is %d", len(bundle.Capabilities), maxCapabilities)
	}
	model := strings.TrimSpace(bundle.Model)
	if explicit := strings.TrimSpace(explicitModel); explicit != "" {
		if model != "" && explicit != model {
			return Prepared{}, errors.New("runtime bundle model conflicts with --model")
		}
		model = explicit
	}
	if model == "" {
		return Prepared{}, errors.New("runtime bundle requires a model in the bundle or an explicit --model")
	}

	prepared := Prepared{
		Model:        model,
		ConfigMode:   "authoritative_bundle",
		BundleSHA256: fmt.Sprintf("%x", digest[:]),
		AgentArgs: []string{
			"--ignore-user-config",
			"--ignore-rules",
			"--strict-config",
		},
	}
	defaultKeys := make([]string, 0, len(authoritativeCodexDefaults))
	for key := range authoritativeCodexDefaults {
		defaultKeys = append(defaultKeys, key)
	}
	sort.Strings(defaultKeys)
	for _, key := range defaultKeys {
		prepared.AgentArgs = append(prepared.AgentArgs, configArg(key, authoritativeCodexDefaults[key])...)
	}
	seen := make(map[string]struct{}, len(bundle.Capabilities))
	seenConfigKeys := make(map[string]string)
	seenServerSlugs := make(map[string]string)
	skillPaths := make([]string, 0)
	for _, capability := range bundle.Capabilities {
		if !safeIDPattern.MatchString(capability.ID) || strings.TrimSpace(capability.Name) == "" || strings.TrimSpace(capability.Description) == "" {
			return Prepared{}, cleanupFailure(skillPaths, "runtime capability requires a safe id, name, and description")
		}
		if err := rejectSecretValues(capability.Configuration, "configuration"); err != nil {
			return Prepared{}, cleanupFailure(skillPaths, fmt.Sprintf("runtime capability %q: %v", capability.ID, err))
		}
		if _, duplicate := seen[capability.ID]; duplicate {
			return Prepared{}, cleanupFailure(skillPaths, fmt.Sprintf("duplicate runtime capability %q", capability.ID))
		}
		seen[capability.ID] = struct{}{}
		switch capability.Kind {
		case "mcp":
			slug, err := mcpServerSlug(capability)
			if err != nil {
				return Prepared{}, cleanupFailure(skillPaths, err.Error())
			}
			if previous, duplicate := seenServerSlugs[slug]; duplicate {
				return Prepared{}, cleanupFailure(skillPaths, fmt.Sprintf("MCP capabilities %q and %q use duplicate effective server_slug %q", previous, capability.ID, slug))
			}
			seenServerSlugs[slug] = capability.ID
			args, err := mcpArgs(capability)
			if err != nil {
				return Prepared{}, cleanupFailure(skillPaths, err.Error())
			}
			prepared.AgentArgs = append(prepared.AgentArgs, args...)
		case "skill":
			path, err := materializeSkill(controlRoot, capability)
			if err != nil {
				return Prepared{}, cleanupFailure(skillPaths, err.Error())
			}
			skillPaths = append(skillPaths, path)
		case "tool":
			key, err := toolConfigKey(capability)
			if err != nil {
				return Prepared{}, cleanupFailure(skillPaths, err.Error())
			}
			if previous, duplicate := seenConfigKeys[key]; duplicate {
				return Prepared{}, cleanupFailure(skillPaths, fmt.Sprintf("tool capabilities %q and %q use duplicate effective config_key %q", previous, capability.ID, key))
			}
			seenConfigKeys[key] = capability.ID
			args, err := toolArgs(capability)
			if err != nil {
				return Prepared{}, cleanupFailure(skillPaths, err.Error())
			}
			prepared.AgentArgs = append(prepared.AgentArgs, args...)
		default:
			return Prepared{}, cleanupFailure(skillPaths, fmt.Sprintf("runtime capability %q has unsupported kind %q", capability.ID, capability.Kind))
		}
	}
	if len(skillPaths) > 0 {
		entries := make([]string, 0, len(skillPaths))
		for _, skillPath := range skillPaths {
			entries = append(entries, "{path="+tomlString(filepath.Join(skillPath, "SKILL.md"))+",enabled=true}")
		}
		prepared.AgentArgs = append(prepared.AgentArgs, configArg("skills.config", "["+strings.Join(entries, ",")+"]")...)
	}
	size := argumentBytes(prepared.AgentArgs)
	if model != "" {
		size += len("--model") + 1 + len(model) + 1
	}
	if size > maxResolvedArgsBytes {
		return Prepared{}, cleanupFailure(skillPaths, fmt.Sprintf("resolved runtime arguments use %d bytes; maximum is %d", size, maxResolvedArgsBytes))
	}
	prepared.cleanup = func() error { return cleanupSkills(skillPaths) }
	return prepared, nil
}

func argumentBytes(args []string) int {
	total := 0
	for _, arg := range args {
		total += len(arg) + 1 // include the argv NUL separator
	}
	return total
}

// Runtime bundles may identify credentials by reference or by the name of an
// environment variable, but they must never carry a credential value. The
// bundle producer enforces the same rule before creating a snapshot; this is
// the final defense-in-depth check immediately before invoking the agent
// process.
func rejectSecretValues(value any, path string) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), "-", "_"))
			for _, secretKey := range []string{"secret", "token", "password", "api_key", "private_key", "authorization"} {
				if normalized == secretKey || strings.HasSuffix(normalized, "_"+secretKey) {
					return fmt.Errorf("contains forbidden secret field %s.%s; use credential_ref or an environment-variable reference", path, key)
				}
			}
			if err := rejectSecretValues(nested, path+"."+key); err != nil {
				return err
			}
		}
	case []any:
		for index, nested := range typed {
			if err := rejectSecretValues(nested, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	}
	return nil
}

func mcpArgs(capability Capability) ([]string, error) {
	var config struct {
		ServerSlug        string   `json:"server_slug"`
		URL               string   `json:"url"`
		EnabledTools      []string `json:"enabled_tools,omitempty"`
		DisabledTools     []string `json:"disabled_tools,omitempty"`
		Required          bool     `json:"required,omitempty"`
		BearerTokenEnvVar string   `json:"bearer_token_env_var,omitempty"`
	}
	if err := decodeConfiguration(capability.Configuration, &config); err != nil {
		return nil, fmt.Errorf("MCP capability %q: %w", capability.ID, err)
	}
	for _, field := range []string{"enabled_tools", "disabled_tools", "required"} {
		if value, explicitlySet := capability.Configuration[field]; explicitlySet && value == nil {
			return nil, fmt.Errorf("MCP capability %q field %s must not be null", capability.ID, field)
		}
	}
	serverSlug, err := mcpServerSlug(capability)
	if err != nil {
		return nil, err
	}
	rawURL := config.URL
	if rawURL == "" || rawURL != strings.TrimSpace(rawURL) {
		return nil, fmt.Errorf("MCP capability %q requires a canonical non-blank url", capability.ID)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, fmt.Errorf("MCP capability %q requires a public HTTPS url", capability.ID)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("MCP capability %q URL must not contain a query or fragment; use bearer_token_env_var for credentials", capability.ID)
	}
	enabledTools, err := validatedStringSet(config.EnabledTools, "enabled_tools")
	if err != nil {
		return nil, fmt.Errorf("MCP capability %q: %w", capability.ID, err)
	}
	disabledTools, err := validatedStringSet(config.DisabledTools, "disabled_tools")
	if err != nil {
		return nil, fmt.Errorf("MCP capability %q: %w", capability.ID, err)
	}
	for tool := range enabledTools {
		if _, conflict := disabledTools[tool]; conflict {
			return nil, fmt.Errorf("MCP capability %q lists tool %q as both enabled and disabled", capability.ID, tool)
		}
	}
	prefix := "mcp_servers." + serverSlug + "."
	args := configArg(prefix+"url", tomlString(parsed.String()))
	args = append(args, configArg(prefix+"required", strconv.FormatBool(config.Required))...)
	if _, explicitlySet := capability.Configuration["bearer_token_env_var"]; explicitlySet {
		value := strings.TrimSpace(config.BearerTokenEnvVar)
		if value == "" || value != config.BearerTokenEnvVar {
			return nil, fmt.Errorf("MCP capability %q bearer_token_env_var must be canonical and non-blank", capability.ID)
		}
		if !validEnvironmentName(value) {
			return nil, fmt.Errorf("MCP capability %q has an invalid bearer_token_env_var", capability.ID)
		}
		args = append(args, configArg(prefix+"bearer_token_env_var", tomlString(value))...)
	}
	if len(config.EnabledTools) > 0 {
		args = append(args, configArg(prefix+"enabled_tools", tomlStringArray(config.EnabledTools))...)
	}
	if len(config.DisabledTools) > 0 {
		args = append(args, configArg(prefix+"disabled_tools", tomlStringArray(config.DisabledTools))...)
	}
	return args, nil
}

func toolArgs(capability Capability) ([]string, error) {
	var config struct {
		ConfigKey string `json:"config_key"`
		Value     any    `json:"value"`
	}
	if err := decodeConfiguration(capability.Configuration, &config); err != nil {
		return nil, fmt.Errorf("tool capability %q: %w", capability.ID, err)
	}
	key := strings.TrimSpace(config.ConfigKey)
	if key != config.ConfigKey || key == "" {
		return nil, fmt.Errorf("tool capability %q requires a non-blank canonical config_key", capability.ID)
	}
	allowed := map[string]func(any) (string, error){
		"web_search":                webSearchValue,
		"features.multi_agent":      booleanToolValue,
		"features.image_generation": booleanToolValue,
	}
	encode, ok := allowed[key]
	if !ok {
		return nil, fmt.Errorf("tool capability %q uses unsupported Codex config key %q", capability.ID, config.ConfigKey)
	}
	value, err := encode(config.Value)
	if err != nil {
		return nil, fmt.Errorf("tool capability %q config key %q: %w", capability.ID, key, err)
	}
	return configArg(key, value), nil
}

func mcpServerSlug(capability Capability) (string, error) {
	serverSlug := capability.ID
	if raw, exists := capability.Configuration["server_slug"]; exists {
		value, ok := raw.(string)
		if !ok {
			return "", fmt.Errorf("MCP capability %q server_slug must be a string", capability.ID)
		}
		serverSlug = strings.TrimSpace(value)
		if serverSlug == "" {
			return "", fmt.Errorf("MCP capability %q server_slug must not be blank", capability.ID)
		} else if serverSlug != value {
			return "", fmt.Errorf("MCP capability %q server_slug must not have surrounding whitespace", capability.ID)
		}
	}
	if !safeIDPattern.MatchString(serverSlug) {
		return "", fmt.Errorf("MCP capability %q has an invalid server_slug", capability.ID)
	}
	return serverSlug, nil
}

func toolConfigKey(capability Capability) (string, error) {
	value, ok := capability.Configuration["config_key"]
	if !ok {
		return "", fmt.Errorf("tool capability %q requires config_key", capability.ID)
	}
	key, ok := value.(string)
	if !ok || strings.TrimSpace(key) == "" || strings.TrimSpace(key) != key {
		return "", fmt.Errorf("tool capability %q requires a non-blank canonical config_key", capability.ID)
	}
	return key, nil
}

func validatedStringSet(values []string, field string) (map[string]struct{}, error) {
	result := make(map[string]struct{}, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" || value != raw {
			return nil, fmt.Errorf("%s entries must be non-blank and have no surrounding whitespace", field)
		}
		if _, duplicate := result[value]; duplicate {
			return nil, fmt.Errorf("%s contains duplicate entry %q", field, value)
		}
		result[value] = struct{}{}
	}
	return result, nil
}

func booleanToolValue(value any) (string, error) {
	boolean, ok := value.(bool)
	if !ok {
		return "", errors.New("value must be a boolean")
	}
	return strconv.FormatBool(boolean), nil
}

func webSearchValue(value any) (string, error) {
	mode, ok := value.(string)
	if !ok {
		return "", errors.New("value must be one of disabled, cached, or live")
	}
	switch mode {
	case "disabled", "cached", "live":
		return tomlString(mode), nil
	default:
		return "", errors.New("value must be one of disabled, cached, or live")
	}
}

func materializeSkill(controlRoot string, capability Capability) (string, error) {
	var config struct {
		Name         string `json:"name"`
		Description  string `json:"description"`
		Instructions string `json:"instructions"`
	}
	if err := decodeConfiguration(capability.Configuration, &config); err != nil {
		return "", fmt.Errorf("skill capability %q: %w", capability.ID, err)
	}
	if _, explicitlySet := capability.Configuration["name"]; explicitlySet && strings.TrimSpace(config.Name) == "" {
		return "", fmt.Errorf("skill capability %q name must not be blank when provided", capability.ID)
	}
	if config.Name == "" {
		config.Name = capability.ID
	}
	if !safeIDPattern.MatchString(config.Name) || strings.TrimSpace(config.Description) == "" || strings.TrimSpace(config.Instructions) == "" {
		return "", fmt.Errorf("skill capability %q requires a safe name, description, and instructions", capability.ID)
	}
	resolvedControlRoot, err := filepath.EvalSymlinks(controlRoot)
	if err != nil {
		return "", fmt.Errorf("resolve managed skill control root: %w", err)
	}
	if !filepath.IsAbs(resolvedControlRoot) {
		return "", errors.New("managed skill control root must be absolute")
	}
	info, err := os.Lstat(resolvedControlRoot)
	if err != nil {
		return "", fmt.Errorf("stat managed skill control root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("managed skill control root must be a real directory")
	}
	root := filepath.Join(resolvedControlRoot, "managed-skills")
	if err := os.Mkdir(root, 0o700); err != nil && !os.IsExist(err) {
		return "", fmt.Errorf("create managed skill root: %w", err)
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return "", fmt.Errorf("stat managed skill root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return "", errors.New("managed skill root must be a real directory")
	}
	dir := filepath.Join(root, "skill-"+capability.ID)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", fmt.Errorf("create managed skill %q without replacing repository content: %w", capability.ID, err)
	}
	document := fmt.Sprintf("---\nname: %s\ndescription: %s\n---\n\n%s\n", config.Name, strconv.Quote(strings.TrimSpace(config.Description)), strings.TrimSpace(config.Instructions))
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(document), 0o600); err != nil {
		_ = os.Remove(dir)
		return "", fmt.Errorf("write managed skill %q: %w", capability.ID, err)
	}
	return dir, nil
}

func cleanupFailure(paths []string, message string) error {
	return errors.Join(errors.New(message), cleanupSkills(paths))
}

func cleanupSkills(paths []string) error {
	var result error
	for index := len(paths) - 1; index >= 0; index-- {
		path := paths[index]
		if !strings.HasPrefix(filepath.Base(path), "skill-") {
			result = errors.Join(result, fmt.Errorf("refuse to remove unexpected managed skill path %q", path))
			continue
		}
		result = errors.Join(result, os.RemoveAll(path))
		removeEmptyParents(filepath.Dir(path), 1)
	}
	return result
}

func removeEmptyParents(path string, count int) {
	for range count {
		if err := os.Remove(path); err != nil {
			return
		}
		path = filepath.Dir(path)
	}
}

func decodeConfiguration(source map[string]any, target any) error {
	encoded, err := json.Marshal(source)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func configArg(key, value string) []string { return []string{"--config", key + "=" + value} }

func tomlString(value string) string { return strconv.Quote(value) }

func tomlStringArray(values []string) string {
	clean := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			clean = append(clean, tomlString(value))
		}
	}
	sort.Strings(clean)
	return "[" + strings.Join(clean, ",") + "]"
}

func validEnvironmentName(value string) bool {
	for index, character := range value {
		if character == '_' || character >= 'A' && character <= 'Z' || index > 0 && character >= '0' && character <= '9' {
			continue
		}
		return false
	}
	return value != ""
}
