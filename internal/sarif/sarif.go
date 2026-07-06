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
	Tool              Tool               `json:"tool"`
	Results           []Result           `json:"results"`
	AutomationDetails *AutomationDetails `json:"automationDetails,omitempty"`
}
type AutomationDetails struct {
	ID string `json:"id"`
}
type Tool struct {
	Driver Driver `json:"driver"`
}
type Driver struct {
	Name  string `json:"name"`
	Rules []Rule `json:"rules,omitempty"`
}
type Rule struct {
	ID                   string    `json:"id"`
	Name                 string    `json:"name,omitempty"`
	DefaultConfiguration *Config   `json:"defaultConfiguration,omitempty"`
	Properties           RuleProps `json:"properties,omitempty"`
}
type Config struct {
	Level string `json:"level,omitempty"`
}
type RuleProps struct {
	Tags             []string `json:"tags,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
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

// Anchor rewrites every result's location in the log to (uri, line). Trivy
// image findings otherwise point at the image name, which is not a file in the
// repository; anchoring them to the chart file that references the image makes
// them valid GitHub code-scanning alerts on that line. A blank uri is a no-op.
func Anchor(l *Log, uri string, line int) {
	if l == nil || uri == "" {
		return
	}
	for ri := range l.Runs {
		for i := range l.Runs[ri].Results {
			loc := Location{PhysicalLocation: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{URI: uri},
			}}
			if line > 0 {
				loc.PhysicalLocation.Region = &Region{StartLine: line}
			}
			l.Runs[ri].Results[i].Locations = []Location{loc}
		}
	}
}

// SetCategory stamps automationDetails.id on every run. GitHub code scanning
// keys an analysis by (tool name, category), so distinct categories stop
// same-named runs (one Trivy run per image) from overwriting each other.
func SetCategory(l *Log, id string) {
	if l == nil {
		return
	}
	for ri := range l.Runs {
		l.Runs[ri].AutomationDetails = &AutomationDetails{ID: id}
	}
}

// CountBySeverity counts results per normalized severity, reading the severity
// from each result's referencing rule (Trivy: tags/security-severity).
func CountBySeverity(l *Log) map[string]int {
	counts := map[string]int{}
	if l == nil {
		return counts
	}
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
	case "none":
		return "info"
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
