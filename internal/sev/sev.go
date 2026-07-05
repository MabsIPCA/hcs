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
