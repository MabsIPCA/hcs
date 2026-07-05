// Package summary renders scan findings as a Markdown PR comment.
package summary

import (
	"fmt"
	"strings"

	"github.com/MabsIPCA/hcs/internal/kicsreport"
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
