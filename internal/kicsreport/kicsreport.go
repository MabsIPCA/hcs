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
		if s == "" {
			continue
		}
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
