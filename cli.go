package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

func runCLI(args []string) int {
	if len(args) == 0 {
		return -1
	}
	switch args[0] {
	case "scan":
		return runCLIScan(args[1:])
	case "update":
		return runCLIUpdate(args[1:])
	case "version":
		fmt.Println("spice dev")
		return 0
	case "help", "-h", "--help":
		printCLIUsage()
		return 0
	default:
		return -1
	}
}

func runCLIScan(args []string) int {
	jsonOut, noRemote, profile, roots, err := parseScanArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if len(roots) == 0 {
		roots = []string{"."}
	}
	index, err := OpenFileIndex()
	if err != nil {
		fmt.Fprintf(os.Stderr, "spice: open index: %v\n", err)
		return 1
	}
	defer index.Close()

	scanner := NewScannerWithOptions(index, func(progress ScanProgress) {
		if jsonOut || progress.Done {
			return
		}
		current := progress.CurrentPath
		if len(current) > 96 {
			current = "..." + current[len(current)-93:]
		}
		fmt.Fprintf(os.Stderr, "\r%s %d%% %d/%d %s", progress.Status, progress.Percent, progress.Processed, progress.Total, current)
	})
	scanner.SetProfile(profile)

	if !noRemote {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if bundle, err := LoadRemoteDetectionBundle(ctx); err == nil {
			scanner.UseRemoteDetectionBundle(bundle)
		} else if !jsonOut {
			fmt.Fprintf(os.Stderr, "spice: no remote checks loaded: %v\n", err)
		}
		cancel()
	}

	start := time.Now()
	findings, err := scanner.Scan(normalizeRoots(roots))
	if !jsonOut {
		fmt.Fprintln(os.Stderr)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "spice: scan failed: %v\n", err)
		return 1
	}
	sortFindings(findings)
	if jsonOut {
		payload := map[string]any{
			"startedAt":  start.Format(time.RFC3339),
			"finishedAt": time.Now().Format(time.RFC3339),
			"roots":      normalizeRoots(roots),
			"findings":   findings,
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(payload); err != nil {
			fmt.Fprintf(os.Stderr, "spice: write json: %v\n", err)
			return 1
		}
		return exitCodeForFindings(findings)
	}

	printCLIFindings(findings, time.Since(start))
	return exitCodeForFindings(findings)
}

func parseScanArgs(args []string) (jsonOut bool, noRemote bool, profile ScanProfile, roots []string, err error) {
	profile = ScanProfileProject
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--json":
			jsonOut = true
		case "--no-remote":
			noRemote = true
		case "--profile":
			i++
			if i >= len(args) {
				return false, false, "", nil, fmt.Errorf("--profile requires project, shai-hulud, or deep")
			}
			profile = ScanProfile(args[i])
			if profile != ScanProfileProject && profile != ScanProfileShaiHulud && profile != ScanProfileDeep {
				return false, false, "", nil, fmt.Errorf("unknown scan profile: %s", args[i])
			}
		case "-h", "--help":
			return false, false, "", nil, fmt.Errorf("usage: spice scan [--json] [--no-remote] [--profile project|shai-hulud|deep] [path ...]")
		default:
			if strings.HasPrefix(arg, "-") {
				return false, false, "", nil, fmt.Errorf("unknown scan option: %s", arg)
			}
			roots = append(roots, arg)
		}
	}
	return jsonOut, noRemote, profile, roots, nil
}

func runCLIUpdate(args []string) int {
	flags := flag.NewFlagSet("update", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	bundle, err := LoadRemoteDetectionBundle(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "spice: update failed: %v\n", err)
		return 1
	}
	fmt.Printf("updated %d detection bundle(s)\n", len(bundle.Packs))
	return 0
}

func printCLIFindings(findings []Finding, duration time.Duration) {
	if len(findings) == 0 {
		fmt.Printf("No issues found in %s.\n", duration.Round(time.Millisecond))
		return
	}
	fmt.Printf("%d issue(s) found in %s:\n\n", len(findings), duration.Round(time.Millisecond))
	for _, finding := range findings {
		fmt.Printf("[%s] %s\n", devCLISeverity(finding.Severity), finding.Path)
		fmt.Printf("  Type: %s\n", devCLIKind(finding.Kind))
		fmt.Printf("  Match: %s\n", finding.Evidence)
		if finding.Remediation != "" {
			fmt.Printf("  Next: %s\n", finding.Remediation)
		}
		fmt.Println()
	}
}

func exitCodeForFindings(findings []Finding) int {
	if len(findings) > 0 {
		return 3
	}
	return 0
}

func devCLISeverity(severity string) string {
	switch severity {
	case "critical":
		return "review now"
	case "high":
		return "check"
	case "medium":
		return "heads up"
	default:
		return "info"
	}
}

func devCLIKind(kind string) string {
	switch kind {
	case "affected-package":
		return "package version"
	case "known-malware-hash":
		return "matched bad file"
	case "campaign-artifact":
		return "suspicious file"
	case "suspicious-install-hook":
		return "install script"
	case "ioc-string":
		return "matched text"
	case "persistence":
		return "startup item"
	default:
		return strings.ReplaceAll(kind, "-", " ")
	}
}

func printCLIUsage() {
	fmt.Println(`Spice

Usage:
  spice scan [--json] [--no-remote] [--profile project|shai-hulud|deep] [path ...]
  spice update
  spice version

Running spice with no subcommand opens the desktop UI.`)
}
