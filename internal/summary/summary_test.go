package summary

import (
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/MabsIPCA/hcs/internal/merge"
	"github.com/MabsIPCA/hcs/internal/sbomio"
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
	// nginx row: Critical=0, High=1, Medium=0, Low=0
	if !strings.Contains(md, "| 0 | 1 | 0 | 0 |") {
		t.Errorf("nginx row should show High=1 (Critical=0,High=1,Medium=0,Low=0)\n---\n%s", md)
	}
	if !strings.HasSuffix(strings.TrimSpace(md), "<!-- hcs-sbom -->") {
		t.Errorf("marker must be last line")
	}
}

func TestRender_SkipsUnratedVuln(t *testing.T) {
	images := []sbomio.Image{{
		BOMRef: "docker.io/library/alpine@3.18", Name: "library/alpine", Version: "3.18",
		Sources: []sbomio.Source{{File: "templates/deploy.yaml", Line: 5}},
	}}
	tb := cdx.NewBOM()
	tb.Components = &[]cdx.Component{{
		Type: cdx.ComponentTypeLibrary, BOMRef: "pkg:apk/busybox@1.36", Name: "busybox", Version: "1.36",
	}}
	// Vulnerability with no Ratings (unrated)
	tb.Vulnerabilities = &[]cdx.Vulnerability{{
		BOMRef:  "CVE-UNRATED",
		ID:      "CVE-2099-0001",
		Ratings: nil,
		Affects: &[]cdx.Affects{{Ref: "pkg:apk/busybox@1.36"}},
	}}
	bom := merge.Merge("mychart", images, map[string]*cdx.BOM{"docker.io/library/alpine@3.18": tb})

	md := Render(bom)

	// The alpine row must exist but show all-zero severity columns
	if !strings.Contains(md, "library/alpine:3.18") {
		t.Errorf("alpine row missing from output\n---\n%s", md)
	}
	if !strings.Contains(md, "| 0 | 0 | 0 | 0 |") {
		t.Errorf("alpine row should show all-zero severity counts\n---\n%s", md)
	}
	// The unrated CVE must NOT appear in the summary output
	if strings.Contains(md, "CVE-2099-0001") {
		t.Errorf("unrated CVE-2099-0001 must not appear in summary\n---\n%s", md)
	}
}

func TestRender_SkipsUnknownSeverityVuln(t *testing.T) {
	images := []sbomio.Image{{
		BOMRef: "docker.io/library/debian@11", Name: "library/debian", Version: "11",
		Sources: []sbomio.Source{{File: "templates/deploy.yaml", Line: 20}},
	}}
	tb := cdx.NewBOM()
	tb.Components = &[]cdx.Component{{
		Type: cdx.ComponentTypeLibrary, BOMRef: "pkg:deb/libc@2.31", Name: "libc", Version: "2.31",
	}}
	// Vulnerability with SeverityUnknown rating
	tb.Vulnerabilities = &[]cdx.Vulnerability{{
		BOMRef:  "CVE-UNKNOWN",
		ID:      "CVE-2099-0002",
		Ratings: &[]cdx.VulnerabilityRating{{Severity: cdx.SeverityUnknown}},
		Affects: &[]cdx.Affects{{Ref: "pkg:deb/libc@2.31"}},
	}}
	bom := merge.Merge("mychart", images, map[string]*cdx.BOM{"docker.io/library/debian@11": tb})

	md := Render(bom)

	if !strings.Contains(md, "library/debian:11") {
		t.Errorf("debian row missing from output\n---\n%s", md)
	}
	if !strings.Contains(md, "| 0 | 0 | 0 | 0 |") {
		t.Errorf("debian row should show all-zero severity counts\n---\n%s", md)
	}
	if strings.Contains(md, "CVE-2099-0002") {
		t.Errorf("unknown-severity CVE-2099-0002 must not appear in summary\n---\n%s", md)
	}
}
