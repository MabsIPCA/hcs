# Unified SARIF Helm Chart Scanner — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace hcs's CycloneDX SBOM output with a unified SARIF 2.1.0 report that combines KICS misconfiguration findings and Trivy image CVEs, surfaced via a PR-comment summary and GitHub code-scanning upload.

**Architecture:** One KICS run (`--experimental-helm-scan --image-bom --report-formats json,sarif`) produces misconfig findings (JSON for accurate severities, SARIF for merge) plus an image inventory. Trivy scans each discovered image (`--format sarif`). A new `internal/sarif` package merges KICS + Trivy SARIF logs by concatenating `.runs[]`; a new `internal/kicsreport` package reads KICS JSON for the summary/gating; `internal/summary` renders two sections. `internal/merge` and Trivy-CycloneDX reading are removed.

**Tech Stack:** Go 1.26, `github.com/CycloneDX/cyclonedx-go` (retained ONLY for reading `kics-image-bom.json` image discovery), standard library `encoding/json` for SARIF and KICS JSON.

## Global Constraints

- Go module: `github.com/MabsIPCA/hcs`; Go 1.26.
- Product name: **"Helm Chart Scanner"** (never "SBOM Scanner"). Binary, repo, module, and image name `ghcr.io/mabsipca/hcs` unchanged.
- Primary output file default: `hcs.sarif` (was `hcs-sbom.json`). Summary default: `hcs-summary.md`.
- Sticky PR-comment marker: `<!-- hcs -->` (was `<!-- hcs-sbom -->`).
- Severity vocabulary (lowercase) and order: `critical > high > medium > low > info`.
- Report outputs are always written; `--fail-on` only affects the process exit code.
- Commit trailer on every commit: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Run `gofmt -w`, `go build ./...`, `go vet ./...`, `go test ./...` green before each commit.

---

## File Structure

- Create `internal/sev/sev.go` (+ `sev_test.go`) — severity normalize/rank/threshold.
- Create `internal/kicsreport/kicsreport.go` (+ `kicsreport_test.go`) — parse KICS `results.json`.
- Create `internal/sarif/sarif.go` (+ `sarif_test.go`) — SARIF structs, `Read`, `Merge`, `CountBySeverity`.
- Modify `internal/runner/runner.go` — `KICSScan`, `TrivyImageSARIF` (replace `KICSImageBOM`/`TrivyImageBOM`).
- Modify `internal/summary/summary.go` — render two sections from the parsed inputs.
- Modify `cmd/hcs/main.go` — orchestration, flags, exit code.
- Delete `internal/merge/` (merge.go + merge_test.go), `internal/sbomio/trivy.go` + `trivy_test.go`, `testdata/trivy-nginx.cdx.json`.
- Keep `internal/sbomio/image.go` (+ `image_test.go`) and `testdata/kics-image-bom.json`.
- Add `testdata/kics-results.json`, `testdata/kics.sarif`, `testdata/trivy.sarif`.
- Modify `action.yml`, `README.md`, `.github/workflows/sbom.yml` (rename), example workflow.

---

## Task 1: `internal/sev` — severity scale

**Files:**
- Create: `internal/sev/sev.go`
- Test: `internal/sev/sev_test.go`

**Interfaces:**
- Produces: `sev.Normalize(string) string`, `sev.Rank(string) int`, `sev.AtLeast(s, threshold string) bool`, `sev.Order() []string` (returns `["critical","high","medium","low","info"]`).

- [ ] **Step 1: Write the failing test**

```go
package sev

import "testing"

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"CRITICAL": "critical", "High": "high", "medium": "medium",
		"LOW": "low", "INFO": "info", "TRACE": "info", "": "", "bogus": "",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q)=%q want %q", in, got, want)
		}
	}
}

func TestRankAndAtLeast(t *testing.T) {
	if Rank("critical") <= Rank("high") {
		t.Fatal("critical must outrank high")
	}
	if Rank("bogus") != 0 {
		t.Fatal("unknown severity ranks 0")
	}
	if !AtLeast("critical", "high") {
		t.Error("critical >= high")
	}
	if AtLeast("low", "high") {
		t.Error("low is not >= high")
	}
	if !AtLeast("high", "high") {
		t.Error("high >= high (inclusive)")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sev/ -v`
Expected: FAIL (build error — undefined: Normalize).

- [ ] **Step 3: Write minimal implementation**

```go
// Package sev is a small severity scale shared across hcs.
package sev

import "strings"

var rank = map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

// Normalize lowercases and maps engine severities to the hcs vocabulary.
// KICS "TRACE" collapses to "info"; unknown values return "".
func Normalize(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "info", "trace":
		return "info"
	}
	return ""
}

// Rank returns a sortable weight; unknown severities are 0.
func Rank(s string) int { return rank[Normalize(s)] }

// AtLeast reports whether s is at least as severe as threshold.
func AtLeast(s, threshold string) bool { return Rank(s) >= Rank(threshold) && Rank(threshold) > 0 }

// Order returns severities from most to least severe.
func Order() []string { return []string{"critical", "high", "medium", "low", "info"} }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/sev/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/sev/
git add internal/sev/
git commit -m "feat(sev): shared severity scale (normalize/rank/threshold)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: `internal/kicsreport` — parse KICS JSON results

**Files:**
- Create: `internal/kicsreport/kicsreport.go`
- Test: `internal/kicsreport/kicsreport_test.go`
- Create: `testdata/kics-results.json`

**Interfaces:**
- Consumes: `sev.Normalize`.
- Produces:
  - `type Finding struct { Query, Severity, File string; Line int }`
  - `type Report struct { Counts map[string]int; Findings []Finding }` (Counts keyed by normalized severity; Findings sorted most-severe first)
  - `kicsreport.Read(path string) (*Report, error)`

- [ ] **Step 1: Create the real fixture**

Create `testdata/kics-results.json` (subset of KICS's JSON schema — `severity_counters`, `queries[].{query_name,severity,files[].{file_name,line}}`):

```json
{
  "severity_counters": { "CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 1, "INFO": 3 },
  "total_counter": 7,
  "queries": [
    { "query_name": "Seccomp Profile Is Not Configured", "severity": "HIGH",
      "files": [ { "file_name": "templates/deployment.yaml", "line": 42 } ] },
    { "query_name": "Container Running As Root", "severity": "CRITICAL",
      "files": [ { "file_name": "templates/deployment.yaml", "line": 40 } ] }
  ]
}
```

- [ ] **Step 2: Write the failing test**

```go
package kicsreport

import "testing"

func TestRead(t *testing.T) {
	r, err := Read("../../testdata/kics-results.json")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if r.Counts["critical"] != 1 || r.Counts["high"] != 2 || r.Counts["info"] != 3 {
		t.Errorf("counts = %v", r.Counts)
	}
	if len(r.Findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(r.Findings))
	}
	// most-severe first
	if r.Findings[0].Severity != "critical" || r.Findings[0].Query != "Container Running As Root" {
		t.Errorf("findings[0] = %+v", r.Findings[0])
	}
	if r.Findings[0].File != "templates/deployment.yaml" || r.Findings[0].Line != 40 {
		t.Errorf("findings[0] location = %+v", r.Findings[0])
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/kicsreport/ -v`
Expected: FAIL (undefined: Read).

- [ ] **Step 4: Write minimal implementation**

```go
// Package kicsreport reads KICS's native JSON results for accurate severities.
package kicsreport

import (
	"encoding/json"
	"os"
	"sort"

	"github.com/MabsIPCA/hcs/internal/sev"
)

type Finding struct {
	Query    string
	Severity string
	File     string
	Line     int
}

type Report struct {
	Counts   map[string]int
	Findings []Finding
}

type rawFile struct {
	FileName string `json:"file_name"`
	Line     int    `json:"line"`
}
type rawQuery struct {
	QueryName string    `json:"query_name"`
	Severity  string    `json:"severity"`
	Files     []rawFile `json:"files"`
}
type rawReport struct {
	SeverityCounters map[string]int `json:"severity_counters"`
	Queries          []rawQuery     `json:"queries"`
}

// Read parses a KICS results.json into normalized counts and sorted findings.
func Read(path string) (*Report, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw rawReport
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	rep := &Report{Counts: map[string]int{}}
	for k, v := range raw.SeverityCounters {
		if n := sev.Normalize(k); n != "" {
			rep.Counts[n] += v
		}
	}
	for _, q := range raw.Queries {
		s := sev.Normalize(q.Severity)
		file, line := "", 0
		if len(q.Files) > 0 {
			file, line = q.Files[0].FileName, q.Files[0].Line
		}
		rep.Findings = append(rep.Findings, Finding{Query: q.QueryName, Severity: s, File: file, Line: line})
	}
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		return sev.Rank(rep.Findings[i].Severity) > sev.Rank(rep.Findings[j].Severity)
	})
	return rep, nil
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/kicsreport/ -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
gofmt -w internal/kicsreport/
git add internal/kicsreport/ testdata/kics-results.json
git commit -m "feat(kicsreport): parse KICS JSON results into severities + findings

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: `internal/sarif` — SARIF structs, Read, Merge, per-log severity counts

**Files:**
- Create: `internal/sarif/sarif.go`
- Test: `internal/sarif/sarif_test.go`
- Create: `testdata/trivy.sarif`, `testdata/kics.sarif`

**Interfaces:**
- Consumes: `sev.Normalize`.
- Produces:
  - `type Log struct` (SARIF 2.1.0: `Version`, `Schema`, `Runs []Run`) with a `Merge(others ...*Log)` semantic via package func.
  - `sarif.Read(path string) (*Log, error)`
  - `sarif.Merge(logs ...*Log) *Log` (new log; `Runs` = concatenation of all input runs; nil inputs skipped)
  - `sarif.CountBySeverity(l *Log) map[string]int` (for a Trivy log: per normalized severity, count of results; severity taken from the referenced rule's `properties.tags`, else `security-severity` CVSS bucket)

- [ ] **Step 1: Create real fixtures**

Create `testdata/trivy.sarif` (minimal but faithful to real Trivy output — rule with severity tag + `security-severity`, two results):

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "tool": { "driver": { "name": "Trivy", "rules": [
        { "id": "CVE-2023-0001",
          "properties": { "tags": ["vulnerability","security","HIGH"], "security-severity": "7.5" } },
        { "id": "CVE-2023-0002",
          "properties": { "tags": ["vulnerability","security","LOW"], "security-severity": "2.0" } }
      ] } },
      "results": [
        { "ruleId": "CVE-2023-0001", "level": "error", "message": { "text": "pkg openssl" },
          "locations": [ { "physicalLocation": { "artifactLocation": { "uri": "library/nginx" } } } ] },
        { "ruleId": "CVE-2023-0002", "level": "note", "message": { "text": "pkg apt" },
          "locations": [ { "physicalLocation": { "artifactLocation": { "uri": "library/nginx" } } } ] }
      ]
    }
  ]
}
```

Create `testdata/kics.sarif` (faithful to KICS: severity only on rule `defaultConfiguration.level`, result `level` absent):

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "tool": { "driver": { "name": "KICS", "rules": [
        { "id": "q-1", "name": "Container Running As Root",
          "defaultConfiguration": { "level": "error" } }
      ] } },
      "results": [
        { "ruleId": "q-1",
          "locations": [ { "physicalLocation": {
            "artifactLocation": { "uri": "templates/deployment.yaml" },
            "region": { "startLine": 40 } } } ] }
      ]
    }
  ]
}
```

- [ ] **Step 2: Write the failing test**

```go
package sarif

import "testing"

func TestReadAndMerge(t *testing.T) {
	trivy, err := Read("../../testdata/trivy.sarif")
	if err != nil {
		t.Fatalf("Read trivy: %v", err)
	}
	kics, err := Read("../../testdata/kics.sarif")
	if err != nil {
		t.Fatalf("Read kics: %v", err)
	}
	merged := Merge(kics, nil, trivy)
	if merged.Version != "2.1.0" {
		t.Errorf("version = %q", merged.Version)
	}
	if len(merged.Runs) != 2 {
		t.Fatalf("want 2 runs (kics+trivy), got %d", len(merged.Runs))
	}
	if merged.Runs[0].Tool.Driver.Name != "KICS" || merged.Runs[1].Tool.Driver.Name != "Trivy" {
		t.Errorf("run order wrong: %s, %s", merged.Runs[0].Tool.Driver.Name, merged.Runs[1].Tool.Driver.Name)
	}
}

func TestCountBySeverity_Trivy(t *testing.T) {
	trivy, _ := Read("../../testdata/trivy.sarif")
	counts := CountBySeverity(trivy)
	if counts["high"] != 1 || counts["low"] != 1 {
		t.Errorf("counts = %v", counts)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/sarif/ -v`
Expected: FAIL (undefined: Read).

- [ ] **Step 4: Write minimal implementation**

```go
// Package sarif reads, merges, and summarizes SARIF 2.1.0 logs.
package sarif

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"

	"github.com/MabsIPCA/hcs/internal/sev"
)

type Log struct {
	Schema  string `json:"$schema,omitempty"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}
type Tool struct {
	Driver Driver `json:"driver"`
}
type Driver struct {
	Name  string `json:"name"`
	Rules []Rule `json:"rules,omitempty"`
}
type Rule struct {
	ID                   string        `json:"id"`
	Name                 string        `json:"name,omitempty"`
	DefaultConfiguration *Config       `json:"defaultConfiguration,omitempty"`
	Properties           RuleProps     `json:"properties,omitempty"`
}
type Config struct {
	Level string `json:"level,omitempty"`
}
type RuleProps struct {
	Tags            []string `json:"tags,omitempty"`
	SecuritySeverity string  `json:"security-severity,omitempty"`
}
type Result struct {
	RuleID    string     `json:"ruleId"`
	Level     string     `json:"level,omitempty"`
	Message   Message    `json:"message"`
	Locations []Location `json:"locations,omitempty"`
}
type Message struct {
	Text string `json:"text,omitempty"`
}
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}
type ArtifactLocation struct {
	URI string `json:"uri,omitempty"`
}
type Region struct {
	StartLine int `json:"startLine,omitempty"`
}

// Read parses a SARIF log from disk.
func Read(path string) (*Log, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var l Log
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

// Merge returns a new SARIF log whose runs are the concatenation of all inputs.
func Merge(logs ...*Log) *Log {
	out := &Log{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []Run{},
	}
	for _, l := range logs {
		if l == nil {
			continue
		}
		out.Runs = append(out.Runs, l.Runs...)
	}
	return out
}

// CountBySeverity counts results per normalized severity, reading the severity
// from each result's referencing rule (Trivy: tags/security-severity).
func CountBySeverity(l *Log) map[string]int {
	counts := map[string]int{}
	for _, run := range l.Runs {
		rules := map[string]Rule{}
		for _, r := range run.Rules() {
			rules[r.ID] = r
		}
		for _, res := range run.Results {
			s := ruleSeverity(rules[res.RuleID])
			if s == "" {
				s = sev.Normalize(levelToSeverity(res.Level))
			}
			if s != "" {
				counts[s]++
			}
		}
	}
	return counts
}

// Rules exposes a run's driver rules.
func (r Run) Rules() []Rule { return r.Tool.Driver.Rules }

func ruleSeverity(r Rule) string {
	for _, t := range r.Properties.Tags {
		if s := sev.Normalize(t); s != "" {
			return s
		}
	}
	if r.Properties.SecuritySeverity != "" {
		if f, err := strconv.ParseFloat(r.Properties.SecuritySeverity, 64); err == nil {
			return cvssBucket(f)
		}
	}
	if r.DefaultConfiguration != nil {
		return sev.Normalize(levelToSeverity(r.DefaultConfiguration.Level))
	}
	return ""
}

// levelToSeverity maps SARIF levels to hcs severities (best effort).
func levelToSeverity(level string) string {
	switch strings.ToLower(level) {
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "note":
		return "low"
	}
	return ""
}

func cvssBucket(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	}
	return ""
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/sarif/ -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
gofmt -w internal/sarif/
git add internal/sarif/ testdata/trivy.sarif testdata/kics.sarif
git commit -m "feat(sarif): SARIF 2.1.0 read/merge + per-severity counts

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: `internal/runner` — KICSScan + TrivyImageSARIF

**Files:**
- Modify: `internal/runner/runner.go`
- Modify: `internal/runner/runner_test.go`

**Interfaces:**
- Consumes: `sbomio` (unchanged).
- Produces:
  - `type KICSOutputs struct { JSON, SARIF, ImageBOM string }`
  - `func (r Runner) KICSScan(scanPath, kicsConfig, outDir string) (KICSOutputs, error)`
  - `func (r Runner) TrivyImageSARIF(ref, trivyConfig, outPath string) error` (writes SARIF to outPath)

- [ ] **Step 1: Update the runner test (stub binary asserts flags + writes outputs)**

Replace the KICS test body in `internal/runner/runner_test.go`. The stub `kics` script must assert the new flags and write all three files; the test checks returned paths:

```go
func TestKICSScan(t *testing.T) {
	dir := t.TempDir()
	kics := filepath.Join(dir, "kics")
	script := `#!/bin/sh
case "$*" in
  *"--report-formats json,sarif"*"--image-bom"*) ;;
  *) echo "missing flags: $*" >&2; exit 3;;
esac
# -o value is the arg after -o
prev=""; out=""
for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
printf '{"severity_counters":{},"queries":[]}' > "$out/results.json"
printf '{"version":"2.1.0","runs":[]}' > "$out/results.sarif"
printf '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[]}' > "$out/kics-image-bom.json"
`
	if err := os.WriteFile(kics, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	got, err := Runner{KICSBin: kics}.KICSScan(".", "", out)
	if err != nil {
		t.Fatalf("KICSScan: %v", err)
	}
	if filepath.Base(got.JSON) != "results.json" ||
		filepath.Base(got.SARIF) != "results.sarif" ||
		filepath.Base(got.ImageBOM) != "kics-image-bom.json" {
		t.Errorf("outputs = %+v", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/runner/ -run TestKICSScan -v`
Expected: FAIL (undefined: KICSScan).

- [ ] **Step 3: Implement `KICSScan` and `TrivyImageSARIF`**

Replace `KICSImageBOM` and `TrivyImageBOM` in `internal/runner/runner.go`:

```go
// KICSOutputs are the files a single KICS scan writes into the output dir.
type KICSOutputs struct {
	JSON     string // results.json  (native severities)
	SARIF    string // results.sarif (for the merged report)
	ImageBOM string // kics-image-bom.json (image discovery)
}

// KICSScan runs KICS once producing JSON + SARIF findings and an image BoM.
func (r Runner) KICSScan(scanPath, kicsConfig, outDir string) (KICSOutputs, error) {
	args := []string{"scan", "-p", scanPath, "--experimental-helm-scan", "--image-bom",
		"--report-formats", "json,sarif", "-o", outDir, "--no-progress"}
	if r.KICSQueryPath != "" {
		args = append(args, "-q", r.KICSQueryPath)
	}
	if kicsConfig != "" {
		args = append(args, "--config", kicsConfig)
	}
	cmd := exec.Command(r.KICSBin, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	// KICS exits non-zero when it finds results; that is not a runner failure.
	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			return KICSOutputs{}, fmt.Errorf("kics scan: %w", err)
		}
	}
	return KICSOutputs{
		JSON:     filepath.Join(outDir, "results.json"),
		SARIF:    filepath.Join(outDir, "results.sarif"),
		ImageBOM: filepath.Join(outDir, "kics-image-bom.json"),
	}, nil
}

// TrivyImageSARIF runs `trivy image <ref> --format sarif --scanners vuln` to outPath.
func (r Runner) TrivyImageSARIF(ref, trivyConfig, outPath string) error {
	args := []string{"image", ref, "--format", "sarif", "--scanners", "vuln", "--output", outPath}
	if trivyConfig != "" {
		args = append(args, "--config", trivyConfig)
	}
	cmd := exec.Command(r.TrivyBin, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("trivy image: %w", err)
	}
	return nil
}
```

Remove the now-unused `cdx` import from `runner.go` if present (the CycloneDX return types are gone). Delete the old Trivy CycloneDX test that referenced `TrivyImageBOM`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/runner/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/runner/
git add internal/runner/
git commit -m "feat(runner): KICSScan (json+sarif+image-bom) and TrivyImageSARIF

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: `internal/summary` — two-section Markdown

**Files:**
- Rewrite: `internal/summary/summary.go`
- Rewrite: `internal/summary/summary_test.go`

**Interfaces:**
- Consumes: `kicsreport.Report`, `sev.Order`.
- Produces:
  - `type ImageVulns struct { Display, Source string; Counts map[string]int }`
  - `summary.Render(mis *kicsreport.Report, images []ImageVulns) string`

- [ ] **Step 1: Write the failing test**

```go
package summary

import (
	"strings"
	"testing"

	"github.com/MabsIPCA/hcs/internal/kicsreport"
)

func TestRender(t *testing.T) {
	mis := &kicsreport.Report{
		Counts: map[string]int{"critical": 1, "high": 2},
		Findings: []kicsreport.Finding{
			{Query: "Container Running As Root", Severity: "critical", File: "templates/deployment.yaml", Line: 40},
		},
	}
	images := []ImageVulns{
		{Display: "library/nginx:1.21", Source: "templates/deploy.yaml:14",
			Counts: map[string]int{"high": 3, "low": 1}},
	}
	out := Render(mis, images)

	for _, want := range []string{
		"## 🔎 HCS Helm Chart scan",
		"### Misconfigurations",
		"Container Running As Root",
		"templates/deployment.yaml:40",
		"### Image vulnerabilities",
		"library/nginx:1.21",
		"<!-- hcs -->",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q\n---\n%s", want, out)
		}
	}
	if strings.Contains(strings.ToLower(out), "sbom") {
		t.Errorf("summary must not mention SBOM:\n%s", out)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/summary/ -v`
Expected: FAIL (Render signature changed / undefined ImageVulns).

- [ ] **Step 3: Rewrite the implementation**

```go
// Package summary renders scan findings as a Markdown PR comment.
package summary

import (
	"fmt"
	"strings"

	"github.com/MabsIPCA/hcs/internal/kicsreport"
	"github.com/MabsIPCA/hcs/internal/sev"
)

const marker = "<!-- hcs -->"

// ImageVulns is one image's per-severity Trivy CVE counts.
type ImageVulns struct {
	Display string
	Source  string
	Counts  map[string]int
}

// Render builds the Markdown summary (misconfigurations + image vulnerabilities).
func Render(mis *kicsreport.Report, images []ImageVulns) string {
	var b strings.Builder
	b.WriteString("## 🔎 HCS Helm Chart scan\n\n")

	b.WriteString("### Misconfigurations\n\n")
	b.WriteString("| Critical | High | Medium | Low | Info |\n|:-:|:-:|:-:|:-:|:-:|\n")
	c := map[string]int{}
	if mis != nil {
		c = mis.Counts
	}
	b.WriteString(fmt.Sprintf("| %d | %d | %d | %d | %d |\n",
		c["critical"], c["high"], c["medium"], c["low"], c["info"]))
	if mis != nil && len(mis.Findings) > 0 {
		b.WriteString("\n<details><summary>Top misconfigurations</summary>\n\n")
		for i, f := range mis.Findings {
			if i >= 20 {
				break
			}
			loc := f.File
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.Line)
			}
			b.WriteString(fmt.Sprintf("- **%s** %s `%s`\n", strings.ToUpper(f.Severity), f.Query, loc))
		}
		b.WriteString("\n</details>\n")
	}

	b.WriteString("\n### Image vulnerabilities\n\n")
	b.WriteString("| Image | Source | Critical | High | Medium | Low |\n")
	b.WriteString("|-------|--------|:-:|:-:|:-:|:-:|\n")
	for _, img := range images {
		src := img.Source
		if src == "" {
			src = "-"
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %d | %d | %d | %d |\n",
			img.Display, src, img.Counts["critical"], img.Counts["high"], img.Counts["medium"], img.Counts["low"]))
	}

	b.WriteString("\n" + marker)
	return b.String()
}

// keep sev import used even if Order() unused directly
var _ = sev.Order
```

Note: remove the `var _ = sev.Order` line if you actually use `sev.Order()`; otherwise drop the `sev` import entirely. (Kept here only to show the dependency; simplest is to not import `sev` in this file.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/summary/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/summary/
git add internal/summary/
git commit -m "feat(summary): two-section (misconfig + image CVE) Markdown render

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: `cmd/hcs/main.go` — orchestrate, flags, exit code; delete dead code

**Files:**
- Rewrite: `cmd/hcs/main.go`
- Delete: `internal/merge/merge.go`, `internal/merge/merge_test.go`
- Delete: `internal/sbomio/trivy.go`, `internal/sbomio/trivy_test.go`, `testdata/trivy-nginx.cdx.json`

**Interfaces:**
- Consumes: `runner.KICSScan/TrivyImageSARIF`, `sbomio.ReadKICSImages`, `kicsreport.Read`, `sarif.Read/Merge/CountBySeverity`, `summary.Render`, `sev.AtLeast`.

- [ ] **Step 1: Delete the removed packages/fixtures**

```bash
git rm internal/merge/merge.go internal/merge/merge_test.go \
       internal/sbomio/trivy.go internal/sbomio/trivy_test.go \
       testdata/trivy-nginx.cdx.json
```

- [ ] **Step 2: Rewrite `cmd/hcs/main.go`**

```go
// Command hcs scans a Helm chart and writes a unified SARIF report + summary.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/MabsIPCA/hcs/internal/kicsreport"
	"github.com/MabsIPCA/hcs/internal/runner"
	"github.com/MabsIPCA/hcs/internal/sarif"
	"github.com/MabsIPCA/hcs/internal/sbomio"
	"github.com/MabsIPCA/hcs/internal/sev"
	"github.com/MabsIPCA/hcs/internal/summary"
)

func main() {
	if len(os.Args) < 3 || os.Args[1] != "scan" {
		fmt.Fprintln(os.Stderr, "usage: hcs scan <path> [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	kicsConfig := fs.String("kics-config", "", "path to KICS config file")
	trivyConfig := fs.String("trivy-config", "", "path to Trivy config file")
	output := fs.String("output", "hcs.sarif", "unified SARIF output path")
	summaryOut := fs.String("summary", "hcs-summary.md", "Markdown summary output path")
	kicsBin := fs.String("kics-bin", "kics", "kics binary")
	trivyBin := fs.String("trivy-bin", "trivy", "trivy binary")
	queryPath := fs.String("kics-query-path", os.Getenv("KICS_QUERIES_PATH"), "KICS query assets path")
	failOn := fs.String("fail-on", "", "exit non-zero if any finding is >= this severity (critical|high|medium|low)")
	fs.Parse(os.Args[3:])
	scanPath := os.Args[2]

	code, err := run(scanPath, *kicsConfig, *trivyConfig, *output, *summaryOut, *failOn,
		runner.Runner{KICSBin: *kicsBin, TrivyBin: *trivyBin, KICSQueryPath: *queryPath})
	if err != nil {
		fmt.Fprintln(os.Stderr, "hcs:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func run(scanPath, kicsConfig, trivyConfig, output, summaryOut, failOn string, r runner.Runner) (int, error) {
	tmp, err := os.MkdirTemp("", "hcs-*")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(tmp)

	kout, err := r.KICSScan(scanPath, kicsConfig, tmp)
	if err != nil {
		return 0, fmt.Errorf("kics: %w", err)
	}
	misc, err := kicsreport.Read(kout.JSON)
	if err != nil {
		return 0, fmt.Errorf("read kics json: %w", err)
	}
	kicsSarif, err := sarif.Read(kout.SARIF)
	if err != nil {
		return 0, fmt.Errorf("read kics sarif: %w", err)
	}
	images, err := sbomio.ReadKICSImages(kout.ImageBOM)
	if err != nil {
		return 0, fmt.Errorf("read kics image-bom: %w", err)
	}

	logs := []*sarif.Log{kicsSarif}
	var imageVulns []summary.ImageVulns
	for i, img := range images {
		out := filepath.Join(tmp, fmt.Sprintf("trivy-%d.sarif", i))
		if err := r.TrivyImageSARIF(img.ScanRef(), trivyConfig, out); err != nil {
			fmt.Fprintf(os.Stderr, "hcs: warning: trivy scan of %s failed: %v\n", img.ScanRef(), err)
			imageVulns = append(imageVulns, summary.ImageVulns{Display: display(img), Source: firstSource(img), Counts: map[string]int{}})
			continue
		}
		tl, err := sarif.Read(out)
		if err != nil {
			return 0, fmt.Errorf("read trivy sarif: %w", err)
		}
		logs = append(logs, tl)
		imageVulns = append(imageVulns, summary.ImageVulns{
			Display: display(img), Source: firstSource(img), Counts: sarif.CountBySeverity(tl),
		})
	}

	merged := sarif.Merge(logs...)
	if err := writeJSON(output, merged); err != nil {
		return 0, err
	}
	if err := os.WriteFile(summaryOut, []byte(summary.Render(misc, imageVulns)), 0o644); err != nil {
		return 0, err
	}
	fmt.Printf("hcs: wrote %s (%d images, %d misconfig findings) and %s\n",
		output, len(images), len(misc.Findings), summaryOut)

	if failOn != "" && exceeds(misc, imageVulns, failOn) {
		fmt.Fprintf(os.Stderr, "hcs: findings at or above %q severity\n", failOn)
		return 1, nil
	}
	return 0, nil
}

func exceeds(misc *kicsreport.Report, images []summary.ImageVulns, threshold string) bool {
	for s, n := range misc.Counts {
		if n > 0 && sev.AtLeast(s, threshold) {
			return true
		}
	}
	for _, img := range images {
		for s, n := range img.Counts {
			if n > 0 && sev.AtLeast(s, threshold) {
				return true
			}
		}
	}
	return false
}

func display(img sbomio.Image) string { return img.Name + ":" + img.Version }

func firstSource(img sbomio.Image) string {
	if len(img.Sources) == 0 {
		return "-"
	}
	s := img.Sources[0]
	if s.Line > 0 {
		return fmt.Sprintf("%s:%d", s.File, s.Line)
	}
	return s.File
}

func writeJSON(path string, v any) (retErr error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); retErr == nil {
			retErr = cerr
		}
	}()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
```

- [ ] **Step 3: Build + vet + full test**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: PASS, no references to `internal/merge` or `ReadTrivyBOM` remain.

- [ ] **Step 4: Commit**

```bash
gofmt -w cmd/hcs/
git add -A
git commit -m "feat(cmd): unified SARIF output, --fail-on gating; drop CycloneDX merge

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: Rebrand + Action code-scanning upload + docs

**Files:**
- Modify: `action.yml`, `README.md`, `.github/workflows/sbom.yml` → rename to `.github/workflows/scan.yml`
- Modify: any remaining "SBOM Scanner" strings.

**Interfaces:** none (docs/CI).

- [ ] **Step 1: Update `action.yml`**

Set `name: "HCS Helm Chart Scanner"`, `description: "Scan a Helm chart with KICS + Trivy and report a unified SARIF of findings"`. Change the `output` input default to `hcs.sarif`. Add input:

```yaml
  fail-on:
    description: "Exit non-zero if any finding is >= this severity (critical|high|medium|low)"
    default: ""
```

In the run step, pass `--fail-on` and `--output`:

```yaml
        ghcr.io/mabsipca/hcs:latest scan "${{ inputs.path }}" \
          --output "${{ inputs.output }}" --summary "hcs-summary.md" \
          ${{ inputs.fail-on && format('--fail-on "{0}"', inputs.fail-on) || '' }} \
          ...
```

Change the sticky-comment marker in the github-script step from `<!-- hcs-sbom -->` to `<!-- hcs -->`. Add a code-scanning upload step (runs even if the scan step failed via `--fail-on`):

```yaml
    - name: Upload SARIF to code scanning
      if: always()
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: ${{ inputs.output }}
```

Update the artifact upload `path` to `${{ inputs.output }}`.

- [ ] **Step 2: Update `README.md`**

Replace title/description "Helm Chart SBOM Scanner" → "Helm Chart Scanner"; describe the unified SARIF output (not CycloneDX SBOM); document `--fail-on`, `--output hcs.sarif`; update the "GitHub Action usage" section to include the `security-events: write` permission and the code-scanning upload; update the example workflow permissions block:

```yaml
permissions:
  contents: read
  pull-requests: write
  security-events: write
```

- [ ] **Step 3: Rename the example workflow**

```bash
git mv .github/workflows/sbom.yml .github/workflows/scan.yml
```
Set `name: Helm Chart Scan`, add `security-events: write` to its `permissions`.

- [ ] **Step 4: Verify no stale "SBOM" references remain**

Run: `grep -rin "sbom" --include=*.go --include=*.yml --include=*.md . | grep -iv "cyclonedx\|kics-image-bom\|image-bom\|docs/superpowers/specs"`
Expected: no product-name "SBOM Scanner" hits (image-bom filename references are fine).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "chore: rebrand to Helm Chart Scanner; action uploads SARIF to code scanning

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 8: End-to-end verification with the real Docker image

**Files:** none (verification only).

- [ ] **Step 1: Build the image and run against a real chart**

```bash
docker build -t hcs-local .
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD:/workspace" -w /workspace hcs-local \
  scan ./testdata/somechart --output /workspace/hcs.sarif --summary /workspace/hcs-summary.md || true
```
(If no bundled chart exists, point at a small Helm chart, e.g. `mad-deployment-service/helm/madgoat`.)

- [ ] **Step 2: Confirm the outputs**

```bash
jq -r '{version, runs:[.runs[].tool.driver.name]}' hcs.sarif   # expect KICS + Trivy runs
grep -c "<!-- hcs -->" hcs-summary.md                           # expect 1
```
Expected: SARIF has a KICS run and one Trivy run per image; summary shows both sections with non-zero counts. Confirm KICS's real SARIF filename is `results.sarif` and JSON is `results.json`; if KICS uses a different output name, adjust `runner.KICSScan` paths and re-run.

- [ ] **Step 3: Confirm `--fail-on`**

```bash
docker run --rm ... hcs-local scan ./chart --fail-on critical; echo "exit=$?"
```
Expected: exit 1 if any critical finding exists, else 0; outputs still written.

- [ ] **Step 4: Final commit if any path fixups were needed**

```bash
git add -A && git commit -m "fix: align KICS output filenames with real binary

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>" || echo "no changes"
```

---

## Self-Review notes

- **Spec coverage:** SARIF pivot (Tasks 3,6), KICS misconfig + Trivy CVE coverage (Tasks 2,4,6), single-KICS-run data flow (Task 4), `internal/sarif` (Task 3), remove `internal/merge`/CycloneDX (Task 6), `--fail-on` (Tasks 1,6), action code-scanning upload + PR comment (Task 7), rename (Task 7), testing (each task), testdata swap (Tasks 2,3,6). Covered.
- **Severity accuracy refinement:** KICS SARIF collapses HIGH+CRITICAL to `error`; the summary and `--fail-on` therefore use KICS **JSON** severities (Task 2), while SARIF is used only for the merged upload. (Resolves spec Open item #1.)
- **Deferred:** Trivy-result chart provenance enrichment (spec Open item #2) is intentionally out of scope; image source appears in the summary table via `firstSource`, not inside the SARIF.
