package main

import (
	"encoding/csv"
	"regexp"
	"strings"
)

type parsedPackageCSV struct {
	Versions          map[string]map[string]bool
	EcosystemVersions map[string]map[string]map[string]bool
}

func parsePackageCSV(raw string) map[string]map[string]bool {
	return parsePackageCSVWithEcosystems(raw).Versions
}

func parsePackageCSVWithEcosystems(raw string) parsedPackageCSV {
	out := parsedPackageCSV{
		Versions:          map[string]map[string]bool{},
		EcosystemVersions: map[string]map[string]map[string]bool{},
	}
	reader := csv.NewReader(strings.NewReader(raw))
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return out
	}
	layout := packageCSVColumnLayout{ecosystemIndex: -1, packageIndex: 0, versionIndex: 1}
	start := 0
	if len(records) > 0 {
		headerLayout := packageCSVLayout(records[0])
		if headerLayout.header {
			layout = headerLayout
			start = 1
		}
	}
	for _, record := range records[start:] {
		if len(record) < 2 {
			continue
		}
		if layout.packageIndex < 0 || layout.versionIndex < 0 || layout.packageIndex >= len(record) || layout.versionIndex >= len(record) {
			continue
		}
		pkg := strings.TrimSpace(record[layout.packageIndex])
		if pkg == "" {
			continue
		}
		ecosystem := ""
		if layout.ecosystemIndex >= 0 && layout.ecosystemIndex < len(record) {
			ecosystem = normalizePackageEcosystem(record[layout.ecosystemIndex])
		}
		for _, version := range parseAffectedVersionField(record[layout.versionIndex]) {
			if ecosystem == "" {
				addAffectedVersion(out.Versions, pkg, version)
				continue
			}
			if out.EcosystemVersions[ecosystem] == nil {
				out.EcosystemVersions[ecosystem] = map[string]map[string]bool{}
			}
			addAffectedVersion(out.EcosystemVersions[ecosystem], pkg, version)
		}
	}
	return out
}

func parseAffectedVersionField(field string) []string {
	exactVersionRE := regexp.MustCompile(`(?:^|[|,])\s*=\s*([^\s,|]+)`)
	numberedVersionRE := regexp.MustCompile(`\bv?\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.-]+)?`)
	seen := map[string]bool{}
	versions := []string{}
	add := func(version string) {
		version = strings.Trim(strings.TrimSpace(version), `"'`)
		if version == "" || seen[version] {
			return
		}
		seen[version] = true
		versions = append(versions, version)
	}
	for _, match := range exactVersionRE.FindAllStringSubmatch(field, -1) {
		if len(match) > 1 {
			add(match[1])
		}
	}
	for _, version := range numberedVersionRE.FindAllString(field, -1) {
		add(version)
	}
	return versions
}

type packageCSVColumnLayout struct {
	header         bool
	ecosystemIndex int
	packageIndex   int
	versionIndex   int
}

func packageCSVLayout(record []string) packageCSVColumnLayout {
	layout := packageCSVColumnLayout{ecosystemIndex: -1, packageIndex: 0, versionIndex: 1}
	headerNames := map[string]int{}
	for index, value := range record {
		key := strings.ToLower(strings.TrimSpace(value))
		if key == "" {
			continue
		}
		headerNames[key] = index
	}
	if len(headerNames) == 0 {
		return layout
	}
	if index, ok := headerNames["ecosystem"]; ok {
		layout.header = true
		layout.ecosystemIndex = index
	}
	for _, key := range []string{"package", "name"} {
		if index, ok := headerNames[key]; ok {
			layout.header = true
			layout.packageIndex = index
			break
		}
	}
	if index, ok := headerNames["version"]; ok {
		layout.header = true
		layout.versionIndex = index
	}
	return layout
}

func addAffectedVersion(target map[string]map[string]bool, pkg, version string) {
	if target[pkg] == nil {
		target[pkg] = map[string]bool{}
	}
	target[pkg][version] = true
}

func normalizePackageEcosystem(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "python", "py", "pypi":
		return "pypi"
	case "node", "nodejs", "javascript", "js", "npm":
		return "npm"
	case "composer", "packagist", "php":
		return "composer"
	case "crates", "crates.io", "cargo", "rust":
		return "crates"
	case "go", "golang", "gomod", "go modules", "go-modules":
		return "go"
	case "nuget", "nuget.org", "dotnet", ".net":
		return "nuget"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}
