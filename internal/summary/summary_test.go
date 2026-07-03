package summary

import (
	"strings"
	"testing"

	"github.com/MabsIPCA/hcs/internal/merge"
	"github.com/MabsIPCA/hcs/internal/sbomio"
	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestRender(t *testing.T) {
	images := []sbomio.Image{{
		BOMRef: "docker.io/library/nginx@1.21", Name: "library/nginx", Version: "1.21",
		Sources: []sbomio.Source{{File: "templates/deploy.yaml", Line: 14}},
	}}
	tb := cdx.NewBOM()
	tb.Components = &[]cdx.Component{{Type: cdx.ComponentTypeLibrary, BOMRef: "pkg:deb/openssl@1.1", Name: "openssl", Version: "1.1"}}
	tb.Vulnerabilities = &[]cdx.Vulnerability{{
		BOMRef: "CVE-9", ID: "CVE-2023-9999",
		Ratings: &[]cdx.VulnerabilityRating{{Severity: cdx.SeverityHigh}},
		Affects: &[]cdx.Affects{{Ref: "pkg:deb/openssl@1.1"}},
	}}
	bom := merge.Merge("mychart", images, map[string]*cdx.BOM{"docker.io/library/nginx@1.21": tb})

	md := Render(bom)

	for _, want := range []string{
		"HCS Helm SBOM scan",
		"library/nginx:1.21",
		"templates/deploy.yaml:14",
		"CVE-2023-9999",
		"<!-- hcs-sbom -->",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("summary missing %q\n---\n%s", want, md)
		}
	}
	if !strings.HasSuffix(strings.TrimSpace(md), "<!-- hcs-sbom -->") {
		t.Errorf("marker must be last line")
	}
}
