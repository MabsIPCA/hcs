package merge

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/MabsIPCA/hcs/internal/sbomio"
)

func fixtureImages() []sbomio.Image {
	return []sbomio.Image{
		{BOMRef: "docker.io/library/nginx@1.21", Name: "library/nginx", Version: "1.21",
			PackageURL: "pkg:docker/library/nginx@1.21",
			Sources:    []sbomio.Source{{File: "templates/deploy.yaml", Line: 14}}},
		{BOMRef: "docker.io/library/redis@7", Name: "library/redis", Version: "7",
			PackageURL: "pkg:docker/library/redis@7"},
	}
}

func trivyBOM(pkgRef, vulnID, sev string) *cdx.BOM {
	b := cdx.NewBOM()
	b.Components = &[]cdx.Component{{Type: cdx.ComponentTypeLibrary, BOMRef: pkgRef, Name: "pkg", Version: "1"}}
	b.Vulnerabilities = &[]cdx.Vulnerability{{
		BOMRef:  vulnID,
		ID:      vulnID,
		Ratings: &[]cdx.VulnerabilityRating{{Severity: cdx.Severity(sev)}},
		Affects: &[]cdx.Affects{{Ref: pkgRef}},
	}}
	return b
}

func TestMerge_NestsPackagesUnderImages(t *testing.T) {
	images := fixtureImages()
	trivy := map[string]*cdx.BOM{
		"docker.io/library/nginx@1.21": trivyBOM("pkg:deb/openssl@1.1", "CVE-1", "high"),
		// redis intentionally missing (scan failed)
	}

	bom := Merge("mychart", images, trivy)

	if bom.Components == nil || len(*bom.Components) != 2 {
		t.Fatalf("want 2 image components, got %v", bom.Components)
	}
	nginx := (*bom.Components)[0]
	if nginx.Type != cdx.ComponentTypeContainer || nginx.BOMRef != "docker.io/library/nginx@1.21" {
		t.Fatalf("nginx component = %+v", nginx)
	}
	// packages nested under the image
	if nginx.Components == nil || len(*nginx.Components) != 1 {
		t.Fatalf("want 1 nested package, got %v", nginx.Components)
	}
	// nested package bom-ref namespaced under the image ref
	nested := (*nginx.Components)[0]
	want := "docker.io/library/nginx@1.21/pkg:deb/openssl@1.1"
	if nested.BOMRef != want {
		t.Errorf("nested bom-ref = %q, want %q", nested.BOMRef, want)
	}
	// provenance carried
	if !hasProp(nginx.Properties, "kics:source:file", "templates/deploy.yaml") {
		t.Errorf("missing provenance on nginx: %+v", nginx.Properties)
	}
	if !hasProp(nginx.Properties, "kics:source:line", "14") {
		t.Errorf("missing line provenance on nginx: %+v", nginx.Properties)
	}
	// vulnerability aggregated and its affects ref rewritten to the namespaced ref
	if bom.Vulnerabilities == nil || len(*bom.Vulnerabilities) != 1 {
		t.Fatalf("want 1 vulnerability, got %v", bom.Vulnerabilities)
	}
	v := (*bom.Vulnerabilities)[0]
	if (*v.Affects)[0].Ref != want {
		t.Errorf("vuln affects ref = %q, want %q", (*v.Affects)[0].Ref, want)
	}
	// vuln BOMRef namespaced under the image ref
	wantVulnRef := "docker.io/library/nginx@1.21/CVE-1"
	if v.BOMRef != wantVulnRef {
		t.Errorf("vuln BOMRef = %q, want %q", v.BOMRef, wantVulnRef)
	}
	// redis has no packages but still appears
	redis := (*bom.Components)[1]
	if redis.BOMRef != "docker.io/library/redis@7" || redis.Components != nil {
		t.Errorf("redis = %+v", redis)
	}
	// metadata target component
	if bom.Metadata == nil || bom.Metadata.Component == nil || bom.Metadata.Component.Name != "mychart" {
		t.Errorf("metadata component = %+v", bom.Metadata)
	}
	// spec version must be CycloneDX 1.5
	if bom.SpecVersion != cdx.SpecVersion1_5 {
		t.Errorf("specVersion = %v, want %v", bom.SpecVersion, cdx.SpecVersion1_5)
	}
}

func TestMerge_RewritesImageLevelVuln(t *testing.T) {
	tb := cdx.NewBOM()
	tb.Metadata = &cdx.Metadata{
		Component: &cdx.Component{
			Type:    cdx.ComponentTypeContainer,
			BOMRef:  "img-self",
			Name:    "library/nginx",
			Version: "1.21",
		},
	}
	tb.Components = &[]cdx.Component{
		{Type: cdx.ComponentTypeLibrary, BOMRef: "pkg-ref", Name: "somepkg", Version: "1.0"},
	}
	tb.Vulnerabilities = &[]cdx.Vulnerability{{
		BOMRef:  "CVE-IMG-1",
		ID:      "CVE-IMG-1",
		Ratings: &[]cdx.VulnerabilityRating{{Severity: cdx.SeverityHigh}},
		Affects: &[]cdx.Affects{{Ref: "img-self"}},
	}}

	images := []sbomio.Image{
		{BOMRef: "docker.io/library/nginx@1.21", Name: "library/nginx", Version: "1.21"},
	}
	bom := Merge("mychart", images, map[string]*cdx.BOM{
		"docker.io/library/nginx@1.21": tb,
	})

	if bom.Vulnerabilities == nil || len(*bom.Vulnerabilities) != 1 {
		t.Fatalf("want 1 vulnerability, got %v", bom.Vulnerabilities)
	}
	v := (*bom.Vulnerabilities)[0]
	if v.Affects == nil || len(*v.Affects) == 0 {
		t.Fatalf("vuln has no affects")
	}
	wantRef := "docker.io/library/nginx@1.21"
	if (*v.Affects)[0].Ref != wantRef {
		t.Errorf("image-level vuln affects ref = %q, want %q", (*v.Affects)[0].Ref, wantRef)
	}
}

func hasProp(props *[]cdx.Property, name, value string) bool {
	if props == nil {
		return false
	}
	for _, p := range *props {
		if p.Name == name && p.Value == value {
			return true
		}
	}
	return false
}
