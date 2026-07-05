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
