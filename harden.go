package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type HardenStatus struct {
	NPM     PackageManagerStatus `json:"npm"`
	Python  PackageManagerStatus `json:"python"`
	Presets []HardenPreset       `json:"presets"`
}

type PackageManagerStatus struct {
	Available     bool               `json:"available"`
	Version       string             `json:"version,omitempty"`
	Path          string             `json:"path,omitempty"`
	ActivePreset  string             `json:"activePreset,omitempty"`
	Settings      []GuardrailSetting `json:"settings"`
	Notes         []string           `json:"notes"`
	LastAppliedAt string             `json:"lastAppliedAt,omitempty"`
	Error         string             `json:"error,omitempty"`
}

type GuardrailSetting struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Wanted      string `json:"wanted,omitempty"`
	Description string `json:"description"`
	Status      string `json:"status"`
}

type HardenPreset struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Settings    []GuardrailSetting `json:"settings"`
}

type HardenApplyRequest struct {
	Preset string `json:"preset"`
}

func (a *App) HardenStatus() HardenStatus {
	return currentHardenStatus("")
}

func (a *App) ApplyHardenPreset(req HardenApplyRequest) (HardenStatus, error) {
	preset, ok := npmHardenPreset(req.Preset)
	if !ok {
		return currentHardenStatus(""), errors.New("unknown hardening preset")
	}
	npmPath, err := findExecutable("npm")
	if err != nil {
		status := currentHardenStatus("")
		status.NPM.Error = "npm was not found on PATH or common install paths"
		return status, errors.New(status.NPM.Error)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, setting := range preset.Settings {
		var commandErr error
		if setting.Wanted == "null" {
			commandErr = runPackageCommand(ctx, npmPath, "config", "delete", setting.Key, "--location=user")
		} else {
			commandErr = runPackageCommand(ctx, npmPath, "config", "set", setting.Key, setting.Wanted, "--location=user")
		}
		if commandErr != nil {
			status := currentHardenStatus("")
			status.NPM.Error = commandErr.Error()
			return status, commandErr
		}
	}
	return currentHardenStatus(time.Now().Format(time.RFC3339)), nil
}

func currentHardenStatus(appliedAt string) HardenStatus {
	npm := npmGuardrailStatus()
	if appliedAt != "" {
		npm.LastAppliedAt = appliedAt
	}
	return HardenStatus{
		NPM:     npm,
		Python:  pythonGuardrailStatus(),
		Presets: npmHardenPresets(),
	}
}

func npmGuardrailStatus() PackageManagerStatus {
	status := PackageManagerStatus{
		Settings: []GuardrailSetting{},
		Notes: []string{
			"npm supports a global rolling package-age guardrail with min-release-age.",
			"These settings are written to the user npm config, not to a project file.",
		},
	}
	npmPath, err := findExecutable("npm")
	if err != nil {
		status.Error = "npm was not found on PATH or common install paths"
		return status
	}
	status.Available = true
	status.Path = npmPath
	status.Version = commandOutput(context.Background(), npmPath, "--version")

	values := map[string]string{}
	for _, key := range []string{"min-release-age", "save-exact", "allow-git", "ignore-scripts"} {
		value := commandOutput(context.Background(), npmPath, "config", "get", key, "--location=user")
		if value == "" {
			value = "null"
		}
		values[key] = value
	}
	recommended, _ := npmHardenPreset("recommended")
	for _, setting := range recommended.Settings {
		value := values[setting.Key]
		status.Settings = append(status.Settings, GuardrailSetting{
			Key:         setting.Key,
			Value:       value,
			Wanted:      setting.Wanted,
			Description: setting.Description,
			Status:      guardrailStatusForKey(setting.Key, value),
		})
	}
	status.ActivePreset = hardenPresetFromValues(values)
	return status
}

func pythonGuardrailStatus() PackageManagerStatus {
	status := PackageManagerStatus{
		Settings: []GuardrailSetting{
			{
				Key:         "pip package age",
				Value:       "unsupported",
				Description: "Stock pip does not provide a global rolling minimum package age setting.",
				Status:      "info",
			},
			{
				Key:         "pip hashes",
				Value:       "available per install",
				Description: "Use pip --require-hashes with locked requirements for stronger repeatability.",
				Status:      "info",
			},
		},
		Notes: []string{
			"For Python, prefer lockfiles, hashes, constraints, or uv when you need package-age cutoffs.",
		},
	}
	if pipPath, err := findExecutable("pip3"); err == nil {
		status.Available = true
		status.Path = pipPath
		status.Version = commandOutput(context.Background(), pipPath, "--version")
	}
	if uvPath, err := findExecutable("uv"); err == nil {
		status.Notes = append(status.Notes, "uv is installed and supports --exclude-newer or UV_EXCLUDE_NEWER for fixed-date cutoffs.")
		status.Settings = append(status.Settings, GuardrailSetting{
			Key:         "uv exclude-newer",
			Value:       "available",
			Description: "uv can limit packages to versions uploaded before a specific date.",
			Status:      "ok",
		})
		_ = uvPath
	}
	return status
}

func npmHardenPresets() []HardenPreset {
	return []HardenPreset{
		mustNPMHardenPreset("recommended"),
		mustNPMHardenPreset("strict"),
		mustNPMHardenPreset("defaults"),
	}
}

func mustNPMHardenPreset(id string) HardenPreset {
	preset, ok := npmHardenPreset(id)
	if !ok {
		panic("unknown npm harden preset: " + id)
	}
	return preset
}

func npmHardenPreset(id string) (HardenPreset, bool) {
	switch id {
	case "recommended":
		return HardenPreset{
			ID:          "recommended",
			Name:        "Recommended",
			Description: "Delay brand-new npm releases, save exact versions, and block Git dependency installs.",
			Settings: []GuardrailSetting{
				{Key: "min-release-age", Wanted: "7", Description: "Avoid npm versions published less than 7 days ago."},
				{Key: "save-exact", Wanted: "true", Description: "Save exact versions instead of ranges for new installs."},
				{Key: "allow-git", Wanted: "none", Description: "Block git dependency specs during npm install."},
				{Key: "ignore-scripts", Wanted: "false", Description: "Keep lifecycle scripts enabled for compatibility."},
			},
		}, true
	case "strict":
		return HardenPreset{
			ID:          "strict",
			Name:        "Strict",
			Description: "Use a longer package-age delay and disable npm lifecycle scripts globally.",
			Settings: []GuardrailSetting{
				{Key: "min-release-age", Wanted: "14", Description: "Avoid npm versions published less than 14 days ago."},
				{Key: "save-exact", Wanted: "true", Description: "Save exact versions instead of ranges for new installs."},
				{Key: "allow-git", Wanted: "none", Description: "Block git dependency specs during npm install."},
				{Key: "ignore-scripts", Wanted: "true", Description: "Disable package lifecycle scripts. This can break native builds and postinstall setup."},
			},
		}, true
	case "defaults":
		return HardenPreset{
			ID:          "defaults",
			Name:        "npm defaults",
			Description: "Return npm guardrail settings to the defaults Spice changes.",
			Settings: []GuardrailSetting{
				{Key: "min-release-age", Wanted: "null", Description: "Remove the minimum package age guardrail."},
				{Key: "save-exact", Wanted: "false", Description: "Allow npm to save semver ranges."},
				{Key: "allow-git", Wanted: "all", Description: "Allow npm git dependency specs."},
				{Key: "ignore-scripts", Wanted: "false", Description: "Allow package lifecycle scripts."},
			},
		}, true
	default:
		return HardenPreset{}, false
	}
}

func hardenPresetFromValues(values map[string]string) string {
	for _, preset := range npmHardenPresets() {
		matches := true
		for _, setting := range preset.Settings {
			if settingStatus(values[setting.Key], setting.Wanted) != "ok" {
				matches = false
				break
			}
		}
		if matches {
			return preset.ID
		}
	}
	return "custom"
}

func settingStatus(value, wanted string) string {
	value = strings.TrimSpace(value)
	wanted = strings.TrimSpace(wanted)
	if wanted == "null" {
		if value == "" || value == "null" || value == "undefined" {
			return "ok"
		}
		return "warn"
	}
	if strings.EqualFold(value, wanted) {
		return "ok"
	}
	return "warn"
}

func guardrailStatusForKey(key, value string) string {
	value = strings.TrimSpace(value)
	switch key {
	case "min-release-age":
		days, err := strconv.Atoi(value)
		if err == nil && days >= 7 {
			return "ok"
		}
		return "warn"
	case "save-exact":
		return settingStatus(value, "true")
	case "allow-git":
		return settingStatus(value, "none")
	case "ignore-scripts":
		if value == "true" || value == "false" {
			return "ok"
		}
		return "warn"
	default:
		return "info"
	}
}

func commandOutput(ctx context.Context, name string, args ...string) string {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func runPackageCommand(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(out))
		if message == "" {
			message = err.Error()
		}
		return errors.New(message)
	}
	return nil
}

func findExecutable(name string) (string, error) {
	if path, err := exec.LookPath(name); err == nil {
		return path, nil
	}
	for _, candidate := range commonExecutablePaths(name) {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", exec.ErrNotFound
}

func commonExecutablePaths(name string) []string {
	return []string{
		filepath.Join("/opt/homebrew/bin", name),
		filepath.Join("/usr/local/bin", name),
		filepath.Join("/usr/bin", name),
	}
}
