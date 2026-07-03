// Package summary renders a merged CycloneDX BOM as a Markdown PR comment.
package summary

import (
	"fmt"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

const marker = "<!-- hcs-sbom -->"

type counts struct{ critical, high, medium, low int }

// Render produces the Markdown summary, ending with the sticky marker.
func Render(bom *cdx.BOM) string {
	// Map every component bom-ref to its owning image bom-ref.
	owner := map[string]string{}
	displayRef := map[string]string{}   // image bom-ref -> "name:version"
	source := map[string]string{}       // image bom-ref -> "file:line"
	order := []string{}

	if bom.Components != nil {
		for _, img := range *bom.Components {
			order = append(order, img.BOMRef)
			owner[img.BOMRef] = img.BOMRef
			displayRef[img.BOMRef] = img.Name + ":" + img.Version
			source[img.BOMRef] = firstSource(img.Properties)
			if img.Components != nil {
				for _, p := range *img.Components {
					owner[p.BOMRef] = img.BOMRef
				}
			}
		}
	}

	perImage := map[string]*counts{}
	type cve struct{ image, id, sev string }
	var cves []cve
	if bom.Vulnerabilities != nil {
		for _, v := range *bom.Vulnerabilities {
			sev := highestSeverity(v.Ratings)
			imgRef := ""
			if v.Affects != nil {
				for _, a := range *v.Affects {
					if o, ok := owner[a.Ref]; ok {
						imgRef = o
						break
					}
				}
			}
			if imgRef == "" || sev == "" {
				continue
			}
			if perImage[imgRef] == nil {
				perImage[imgRef] = &counts{}
			}
			bump(perImage[imgRef], sev)
			cves = append(cves, cve{image: displayRef[imgRef], id: v.ID, sev: sev})
		}
	}

	var b strings.Builder
	b.WriteString("## 🔎 HCS Helm SBOM scan\n\n")
	b.WriteString("| Image | Source | Critical | High | Medium | Low |\n")
	b.WriteString("|-------|--------|:-:|:-:|:-:|:-:|\n")
	for _, ref := range order {
		c := perImage[ref]
		if c == nil {
			c = &counts{}
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %d | %d | %d | %d |\n",
			displayRef[ref], source[ref], c.critical, c.high, c.medium, c.low))
	}

	if len(cves) > 0 {
		sort.Slice(cves, func(i, j int) bool { return sevRank(cves[i].sev) > sevRank(cves[j].sev) })
		b.WriteString("\n<details><summary>Top CVEs</summary>\n\n")
		limit := len(cves)
		if limit > 20 {
			limit = 20
		}
		for _, c := range cves[:limit] {
			b.WriteString(fmt.Sprintf("- **%s** `%s` in `%s`\n", strings.ToUpper(c.sev), c.id, c.image))
		}
		b.WriteString("\n</details>\n")
	}

	b.WriteString("\n" + marker)
	return b.String()
}

func firstSource(props *[]cdx.Property) string {
	if props == nil {
		return "-"
	}
	file, line := "", ""
	for _, p := range *props {
		if p.Name == "kics:source:file" && file == "" {
			file = p.Value
		}
		if p.Name == "kics:source:line" && line == "" {
			line = p.Value
		}
	}
	if file == "" {
		return "-"
	}
	if line == "" {
		return file
	}
	return file + ":" + line
}

func highestSeverity(ratings *[]cdx.VulnerabilityRating) string {
	best := ""
	if ratings == nil {
		return best
	}
	for _, r := range *ratings {
		s := strings.ToLower(string(r.Severity))
		if sevRank(s) > sevRank(best) {
			best = s
		}
	}
	return best
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func bump(c *counts, sev string) {
	switch sev {
	case "critical":
		c.critical++
	case "high":
		c.high++
	case "medium":
		c.medium++
	case "low":
		c.low++
	}
}
