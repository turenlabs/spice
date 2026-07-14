package main

import (
	"archive/zip"
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestNuGetManifestDetection(t *testing.T) {
	tests := []struct {
		name     string
		base     string
		content  string
		evidence string
	}{
		{
			name:     "C sharp project exact singleton version",
			base:     "App.csproj",
			content:  `<Project><ItemGroup><PackageReference Include="Braintree.Net" Version="[3.36.1]" /></ItemGroup></Project>`,
			evidence: "Braintree.Net@3.36.1 in nuget-project",
		},
		{
			name:     "F sharp project nested version",
			base:     "App.fsproj",
			content:  `<Project><ItemGroup><PackageReference Include="Braintree.Net"><Version>[3.36.1]</Version></PackageReference></ItemGroup></Project>`,
			evidence: "Braintree.Net@3.36.1 in nuget-project",
		},
		{
			name:     "central package management",
			base:     "Directory.Packages.props",
			content:  `<Project><ItemGroup><PackageVersion Include="Braintree.Net" Version="[3.36.1]" /></ItemGroup></Project>`,
			evidence: "Braintree.Net@3.36.1 in nuget-project",
		},
		{
			name:     "custom props update and nested version",
			base:     "dependencies.props",
			content:  `<Project><ItemGroup><PackageVersion Update="Braintree.Net"><Version>[3.36.1]</Version></PackageVersion></ItemGroup></Project>`,
			evidence: "Braintree.Net@3.36.1 in nuget-project",
		},
		{
			name:     "global package reference exact singleton",
			base:     "Directory.Packages.props",
			content:  `<Project><ItemGroup><GlobalPackageReference Include="Braintree.Net" Version="[3.36.1]" /></ItemGroup></Project>`,
			evidence: "Braintree.Net@3.36.1 in nuget-project",
		},
		{
			name:     "packages config case insensitive ID",
			base:     "packages.config",
			content:  `<packages><package id="braintree.net" version="3.36.1" targetFramework="net48" /></packages>`,
			evidence: "braintree.net@3.36.1 in packages.config",
		},
		{
			name: "packages lock resolved version",
			base: "packages.lock.json",
			content: `{
				"version": 1,
				"dependencies": {
					"net8.0": {
						"Braintree.Net": {"type":"Direct","requested":"[3.0.0, )","resolved":"3.36.1"}
					}
				}
			}`,
			evidence: "Braintree.Net@3.36.1 in packages.lock.json",
		},
		{
			name: "project assets package library",
			base: "project.assets.json",
			content: `{
				"version": 3,
				"libraries": {
					"Braintree.Net/3.36.1": {"type":"package"},
					"Local.Project/1.0.0": {"type":"project"}
				}
			}`,
			evidence: "Braintree.Net@3.36.1 in project.assets.json",
		},
		{
			name:     "nuspec package identity",
			base:     "Braintree.Net.nuspec",
			content:  `<package><metadata><id>Braintree.Net</id><version>3.36.1</version></metadata></package>`,
			evidence: "Braintree.Net@3.36.1 in nuspec",
		},
		{
			name:     "nuspec exact singleton dependency",
			base:     "Carrier.nuspec",
			content:  `<package><metadata><id>Safe.Carrier</id><version>1.0.0</version><dependencies><dependency id="DependencyInjector.Core" version="[1.4.1]" /></dependencies></metadata></package>`,
			evidence: "DependencyInjector.Core@1.4.1 in nuspec",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := scanNuGetTestFile(test.base, []byte(test.content), nuGetTestPack())
			assertSeverityContains(t, findings, "critical", "affected-package", test.evidence)
		})
	}
}

func TestNuGetUnaffectedAndUnresolvedConstraintsAreClean(t *testing.T) {
	tests := []struct {
		name    string
		base    string
		content string
	}{
		{
			name:    "different version",
			base:    "App.csproj",
			content: `<Project><ItemGroup><PackageReference Include="Braintree.Net" Version="[3.36.2]" /></ItemGroup></Project>`,
		},
		{
			name:    "bare project minimum is not affected",
			base:    "App.vbproj",
			content: `<Project><ItemGroup><PackageReference Include="Braintree.Net" Version="3.36.2" /></ItemGroup></Project>`,
		},
		{
			name:    "range with unrelated minimum is not solved broadly",
			base:    "App.vbproj",
			content: `<Project><ItemGroup><PackageReference Include="Braintree.Net" Version="[3.36.0, 3.36.2]" /></ItemGroup></Project>`,
		},
		{
			name:    "exclusive affected lower bound cannot resolve the bound",
			base:    "App.vbproj",
			content: `<Project><ItemGroup><PackageReference Include="Braintree.Net" Version="(3.36.1, 4.0.0)" /></ItemGroup></Project>`,
		},
		{
			name:    "MSBuild property is not resolved version",
			base:    "App.csproj",
			content: `<Project><ItemGroup><PackageReference Include="Braintree.Net" Version="$(BraintreeVersion)" /></ItemGroup></Project>`,
		},
		{
			name:    "nuspec dependency shape outside nuspec",
			base:    "App.csproj",
			content: `<Project><CustomMetadata><dependency id="Braintree.Net" version="3.36.1" /></CustomMetadata></Project>`,
		},
		{
			name: "project library is not NuGet package",
			base: "project.assets.json",
			content: `{
				"libraries": {"Braintree.Net/3.36.1":{"type":"project"}}
			}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := scanNuGetTestFile(test.base, []byte(test.content), nuGetTestPack())
			assertNoKind(t, findings, "affected-package")
		})
	}
}

func TestNuGetAffectedConstraintExposure(t *testing.T) {
	tests := []struct {
		name     string
		base     string
		content  string
		evidence string
	}{
		{
			name:     "bare project minimum",
			base:     "App.csproj",
			content:  `<Project><ItemGroup><PackageReference Include="Braintree.Net" Version="3.36.1" /></ItemGroup></Project>`,
			evidence: `Braintree.Net constraint "3.36.1" can resolve known affected version 3.36.1 in nuget-project; installed version is not established`,
		},
		{
			name:     "bare global package minimum",
			base:     "Directory.Packages.props",
			content:  `<Project><ItemGroup><GlobalPackageReference Include="Braintree.Net" Version="3.36.1" /></ItemGroup></Project>`,
			evidence: `Braintree.Net constraint "3.36.1" can resolve known affected version 3.36.1 in nuget-project; installed version is not established`,
		},
		{
			name:     "inclusive lower bound",
			base:     "App.vbproj",
			content:  `<Project><ItemGroup><PackageReference Include="Braintree.Net" Version="[3.36.1, )" /></ItemGroup></Project>`,
			evidence: `Braintree.Net constraint "[3.36.1, )" can resolve known affected version 3.36.1 in nuget-project; installed version is not established`,
		},
		{
			name:     "bare nuspec dependency minimum",
			base:     "Carrier.nuspec",
			content:  `<package><metadata><id>Safe.Carrier</id><version>1.0.0</version><dependencies><dependency id="DependencyInjector.Core" version="1.4.1" /></dependencies></metadata></package>`,
			evidence: `DependencyInjector.Core constraint "1.4.1" can resolve known affected version 1.4.1 in nuspec; installed version is not established`,
		},
		{
			name:     "nuspec inclusive lower bound",
			base:     "Carrier.nuspec",
			content:  `<package><metadata><id>Safe.Carrier</id><version>1.0.0</version><dependencies><dependency id="DependencyInjector.Core" version="[1.4.1, 2.0.0)" /></dependencies></metadata></package>`,
			evidence: `DependencyInjector.Core constraint "[1.4.1, 2.0.0)" can resolve known affected version 1.4.1 in nuspec; installed version is not established`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := scanNuGetTestFile(test.base, []byte(test.content), nuGetTestPack())
			assertSeverityContains(t, findings, "high", "affected-package-constraint", test.evidence)
			assertNoKind(t, findings, "affected-package")
			for _, finding := range findings {
				if finding.Kind != "affected-package-constraint" {
					continue
				}
				if finding.Confidence != "exposure" {
					t.Errorf("constraint confidence = %q, want exposure", finding.Confidence)
				}
				if !strings.Contains(finding.Remediation, "packages.lock.json") || !strings.Contains(finding.Remediation, "resolved version") {
					t.Errorf("constraint remediation should direct resolved-version triage: %q", finding.Remediation)
				}
			}
		})
	}
	if got := devCLIKind("affected-package-constraint"); got != "package constraint" {
		t.Fatalf("devCLIKind(affected-package-constraint) = %q, want package constraint", got)
	}
}

func TestNuGetBareProjectConstraintRemainsInventoryWithoutExactClaim(t *testing.T) {
	content := []byte(`<Project><ItemGroup><PackageReference Include="Braintree.Net" Version="3.36.1" /></ItemGroup></Project>`)
	packages := ExtractPackagesFromBytes(filepath.Join("repo", "App.csproj"), content)
	if len(packages) != 1 || packages[0].Name != "Braintree.Net" || packages[0].Version != "3.36.1" {
		t.Fatalf("bare project constraint inventory = %#v, want Braintree.Net 3.36.1", packages)
	}
	findings := scanNuGetTestFile("App.csproj", content, nuGetTestPack())
	assertSeverityContains(t, findings, "high", "affected-package-constraint", `constraint "3.36.1" can resolve known affected version 3.36.1`)
	assertNoKind(t, findings, "affected-package")
}

func TestNuGetAffectedRowDoesNotCrossMatchNPM(t *testing.T) {
	packageJSON := []byte(`{"dependencies":{"Braintree.Net":"3.36.1"}}`)
	findings := scanNuGetTestFile("package.json", packageJSON, nuGetTestPack())
	assertNoKind(t, findings, "affected-package")
}

func TestNuGetAffectedRowGuardPreservesLegacyRows(t *testing.T) {
	if NewMiniShaiHuludDetectionWithRemote(&RemoteDetectionPack{
		AffectedVersionsByEcosystem: map[string]map[string]map[string]bool{
			"npm": {"Braintree.Net": {"3.36.1": true}},
		},
	}).hasAffectedPackageRows("nuget") {
		t.Fatal("npm-only affected rows should not trigger NuGet manifest parsing")
	}

	legacyPack := &RemoteDetectionPack{
		ID:               "legacy-package-rows",
		Campaign:         "Legacy unscoped package rows",
		AffectedVersions: map[string]map[string]bool{"Braintree.Net": {"3.36.1": true}},
	}
	detection := NewMiniShaiHuludDetectionWithRemote(legacyPack)
	if !detection.hasAffectedPackageRows("nuget") {
		t.Fatal("legacy unscoped affected rows must retain NuGet applicability")
	}
	findings := scanNuGetTestFile("App.csproj", []byte(`<Project><ItemGroup><PackageReference Include="Braintree.Net" Version="[3.36.1]" /></ItemGroup></Project>`), legacyPack)
	assertFinding(t, findings, "affected-package", "Braintree.Net@3.36.1 in nuget-project")
}

func TestNuGetManifestInventoryExtraction(t *testing.T) {
	tests := []struct {
		name    string
		base    string
		content string
		want    map[string]string
	}{
		{
			name: "project and exact bracket normalization",
			base: "App.csproj",
			content: `<Project><ItemGroup>
				<PackageReference Include="Braintree.Net" Version="[3.36.1]" />
				<PackageReference Include="DependencyInjector.Core"><Version>[1.4.1]</Version></PackageReference>
			</ItemGroup></Project>`,
			want: map[string]string{"Braintree.Net": "3.36.1", "DependencyInjector.Core": "1.4.1"},
		},
		{
			name: "project declarations retain minimum and range constraints",
			base: "App.csproj",
			content: `<Project><ItemGroup>
				<PackageReference Include="Braintree.Net" Version="3.36.1" />
				<PackageReference Include="DependencyInjector.Core" Version="[1.4.1, 2.0.0)" />
			</ItemGroup></Project>`,
			want: map[string]string{"Braintree.Net": "3.36.1", "DependencyInjector.Core": "[1.4.1, 2.0.0)"},
		},
		{
			name: "packages lock dedupes target frameworks",
			base: "packages.lock.json",
			content: `{"dependencies":{
				"net8.0":{"Braintree.Net":{"resolved":"3.36.1"}},
				"net9.0":{"Braintree.Net":{"resolved":"3.36.1"}}
			}}`,
			want: map[string]string{"Braintree.Net": "3.36.1"},
		},
		{
			name: "assets excludes project libraries",
			base: "project.assets.json",
			content: `{"libraries":{
				"Braintree.Net/3.36.1":{"type":"package"},
				"DependencyInjector.Core/1.4.1":{"type":"package"},
				"Local.Project/1.0.0":{"type":"project"}
			}}`,
			want: map[string]string{"Braintree.Net": "3.36.1", "DependencyInjector.Core": "1.4.1"},
		},
		{
			name: "nuspec identity and dependency",
			base: "Braintree.Net.nuspec",
			content: `<package><metadata>
				<id>Braintree.Net</id><version>3.36.1</version>
				<dependencies><dependency id="DependencyInjector.Core" version="[1.4.1]" /></dependencies>
			</metadata></package>`,
			want: map[string]string{"Braintree.Net": "3.36.1", "DependencyInjector.Core": "1.4.1"},
		},
		{
			name: "nuspec dependencies retain minimum and range constraints",
			base: "Carrier.nuspec",
			content: `<package><metadata>
				<id>Safe.Carrier</id><version>1.0.0</version>
				<dependencies>
					<dependency id="DependencyInjector.Core" version="1.4.1" />
					<dependency id="Braintree.Net" version="[3.36.1, 4.0.0)" />
				</dependencies>
			</metadata></package>`,
			want: map[string]string{
				"Safe.Carrier":            "1.0.0",
				"DependencyInjector.Core": "1.4.1",
				"Braintree.Net":           "[3.36.1, 4.0.0)",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packages := ExtractPackagesFromBytes(filepath.Join("repo", test.base), []byte(test.content))
			got := map[string]string{}
			for _, pkg := range packages {
				if pkg.Ecosystem != "nuget" {
					t.Fatalf("package ecosystem = %q, want nuget: %#v", pkg.Ecosystem, pkg)
				}
				got[pkg.Name] = pkg.Version
			}
			if len(got) != len(test.want) {
				t.Fatalf("inventory = %#v, want %#v", got, test.want)
			}
			for name, version := range test.want {
				if got[name] != version {
					t.Errorf("inventory[%q] = %q, want %q (all: %#v)", name, got[name], version, got)
				}
			}
		})
	}
}

func TestNuGetScanGatesAndAliases(t *testing.T) {
	for _, path := range []string{
		"repo/App.csproj",
		"repo/App.fsproj",
		"repo/App.vbproj",
		"repo/Directory.Packages.props",
		"repo/dependencies.props",
		"repo/packages.config",
		"repo/packages.lock.json",
		"repo/obj/project.assets.json",
		"cache/Braintree.Net.nuspec",
	} {
		if !isNuGetManifestBase(filepath.Base(path)) {
			t.Errorf("expected %q to be a NuGet manifest", path)
		}
		if !textCandidate(path) {
			t.Errorf("expected %q to be a text candidate", path)
		}
		if got := classifyScanFile(path, 2048, nil); got != scanContent {
			t.Errorf("%q: classifyScanFile = %v, want scanContent", path, got)
		}
		if got := manifestEcosystem(FileContext{Base: filepath.Base(path)}); got != "nuget" {
			t.Errorf("%q: manifestEcosystem = %q, want nuget", path, got)
		}
	}
	for _, alias := range []string{"nuget", "NuGet.org", "dotnet", ".NET"} {
		if got := normalizePackageEcosystem(alias); got != "nuget" {
			t.Errorf("normalizePackageEcosystem(%q) = %q, want nuget", alias, got)
		}
	}
	if got := classifyScanFile("cache/Braintree.Net.3.36.1.nupkg", 4096, nil); got != scanContent {
		t.Fatalf("NuGet archive classifyScanFile = %v, want scanContent", got)
	}
	if !isPackageArchiveBase("braintree.net.3.36.1.nupkg") {
		t.Fatal(".nupkg should be recognized as a package archive")
	}
}

func TestNuGetPackageArchiveScansNuspec(t *testing.T) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	member, err := writer.Create("Braintree.Net.nuspec")
	if err != nil {
		t.Fatal(err)
	}
	_, err = member.Write([]byte(`<package><metadata><id>Braintree.Net</id><version>3.36.1</version></metadata></package>`))
	if err != nil {
		t.Fatal(err)
	}
	lockMember, err := writer.Create("packages.lock.json")
	if err != nil {
		t.Fatal(err)
	}
	_, err = lockMember.Write([]byte(`{"dependencies":{"net8.0":{"DependencyInjector.Core":{"resolved":"1.4.1"}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	findings := scanNuGetTestFile("Braintree.Net.3.36.1.nupkg", archive.Bytes(), nuGetTestPack())
	assertFinding(t, findings, "affected-package", "Braintree.Net@3.36.1 in nuspec")
	assertFinding(t, findings, "affected-package", "DependencyInjector.Core@1.4.1 in packages.lock.json")
	foundVirtualPath := false
	for _, finding := range findings {
		if finding.Kind == "affected-package" && strings.Contains(finding.Path, ".nupkg!Braintree.Net.nuspec") {
			foundVirtualPath = true
		}
	}
	if !foundVirtualPath {
		t.Fatalf("affected package finding should identify the archive member: %#v", findings)
	}
}

func TestNuGetParserRejectsOversizedInMemoryManifest(t *testing.T) {
	content := bytes.Repeat([]byte("x"), 33)
	if got, ok := readBoundedPackageData("App.csproj", content, 32); ok || got != nil {
		t.Fatalf("oversized manifest should be rejected: ok=%v len=%d", ok, len(got))
	}
}

func nuGetTestPack() *RemoteDetectionPack {
	return &RemoteDetectionPack{
		ID:       "braintree-nuget-2026-07",
		Campaign: "Braintree.Net NuGet typosquat July 2026",
		AffectedVersionsByEcosystem: map[string]map[string]map[string]bool{
			"nuget": {
				"Braintree.Net":           {"3.36.1": true},
				"DependencyInjector.Core": {"1.4.1": true},
			},
		},
	}
}

func scanNuGetTestFile(base string, data []byte, pack *RemoteDetectionPack) []Finding {
	detection := NewMiniShaiHuludDetectionWithRemote(pack)
	path := filepath.Join("repo", base)
	findings := []Finding{}
	detection.ScanFile(FileContext{Path: path, Base: base, Slash: filepath.ToSlash(path), Data: data}, func(finding Finding) {
		findings = append(findings, finding)
	})
	return dedupeFindings(findings)
}

func BenchmarkNuGetManifestWithoutNuGetRows(b *testing.B) {
	detection := NewMiniShaiHuludDetectionWithRemote(&RemoteDetectionPack{
		AffectedVersionsByEcosystem: map[string]map[string]map[string]bool{
			"npm": {"unrelated-package": {"1.0.0": true}},
		},
	})
	file := FileContext{
		Path: "App.csproj",
		Base: "App.csproj",
		Data: []byte(`<Project><ItemGroup><PackageReference Include="Braintree.Net" Version="[3.36.1]" /></ItemGroup></Project>`),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		detection.scanNuGetManifest(file, func(Finding) {})
	}
}
