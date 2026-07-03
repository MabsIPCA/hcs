package merge

import (
	"testing"

	"github.com/MabsIPCA/hcs/internal/sbomio"
	cdx "github.com/CycloneDX/cyclonedx-go"
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
	// vulnerability aggregated and its affects ref rewritten to the namespaced ref
	if bom.Vulnerabilities == nil || len(*bom.Vulnerabilities) != 1 {
		t.Fatalf("want 1 vulnerability, got %v", bom.Vulnerabilities)
	}
	v := (*bom.Vulnerabilities)[0]
	if (*v.Affects)[0].Ref != want {
		t.Errorf("vuln affects ref = %q, want %q", (*v.Affects)[0].Ref, want)
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
