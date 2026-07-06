package sarif

import (
	"strings"
	"testing"
)

func TestReadAndMerge(t *testing.T) {
	trivy, err := Read("../../testdata/trivy.sarif")
	if err != nil {
		t.Fatalf("Read trivy: %v", err)
	}
	kics, err := Read("../../testdata/kics.sarif")
	if err != nil {
		t.Fatalf("Read kics: %v", err)
	}
	merged := Merge(kics, nil, trivy)
	if merged.Version != "2.1.0" {
		t.Errorf("version = %q", merged.Version)
	}
	if len(merged.Runs) != 2 {
		t.Fatalf("want 2 runs (kics+trivy), got %d", len(merged.Runs))
	}
	if merged.Runs[0].Tool.Driver.Name != "KICS" || merged.Runs[1].Tool.Driver.Name != "Trivy" {
		t.Errorf("run order wrong: %s, %s", merged.Runs[0].Tool.Driver.Name, merged.Runs[1].Tool.Driver.Name)
	}
}

func TestCountBySeverity_Trivy(t *testing.T) {
	trivy, _ := Read("../../testdata/trivy.sarif")
	counts := CountBySeverity(trivy)
	if counts["high"] != 1 || counts["low"] != 1 {
		t.Errorf("counts = %v", counts)
	}
}

func TestCountBySeverity_KICSLevelFallback(t *testing.T) {
	kics, err := Read("../../testdata/kics.sarif")
	if err != nil {
		t.Fatalf("Read kics: %v", err)
	}
	counts := CountBySeverity(kics)
	// kics.sarif has one rule with defaultConfiguration.level "error" -> high
	if counts["high"] != 1 {
		t.Errorf("counts = %v, want high=1", counts)
	}
}

func TestAnchor(t *testing.T) {
	// trivy.sarif results point at the image name; anchor them to a chart file.
	trivy, err := Read("../../testdata/trivy.sarif")
	if err != nil {
		t.Fatalf("Read trivy: %v", err)
	}
	Anchor(trivy, "helm/app/values.yaml", 42)
	for _, run := range trivy.Runs {
		if len(run.Results) == 0 {
			t.Fatal("fixture must have results")
		}
		for _, res := range run.Results {
			if len(res.Locations) != 1 {
				t.Fatalf("want 1 location, got %d", len(res.Locations))
			}
			pl := res.Locations[0].PhysicalLocation
			if pl.ArtifactLocation.URI != "helm/app/values.yaml" {
				t.Errorf("uri = %q, want chart file", pl.ArtifactLocation.URI)
			}
			if pl.Region == nil || pl.Region.StartLine != 42 {
				t.Errorf("region = %+v, want startLine 42", pl.Region)
			}
		}
	}

	// blank uri is a no-op (keeps the original image-name location)
	other, _ := Read("../../testdata/trivy.sarif")
	Anchor(other, "", 0)
	if other.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI == "helm/app/values.yaml" {
		t.Error("blank uri should not rewrite locations")
	}
}

func TestPrefixMessages(t *testing.T) {
	trivy, _ := Read("../../testdata/trivy.sarif")
	const prefix = "Image `library/nginx:1.21.0`: "
	PrefixMessages(trivy, prefix)
	for _, run := range trivy.Runs {
		if len(run.Results) == 0 {
			t.Fatal("fixture must have results")
		}
		for _, res := range run.Results {
			if !strings.HasPrefix(res.Message.Text, prefix) {
				t.Errorf("message not prefixed with image: %q", res.Message.Text)
			}
		}
	}
}

func TestSetCategory(t *testing.T) {
	trivy, _ := Read("../../testdata/trivy.sarif")
	SetCategory(trivy, "trivy/library/nginx:1.21")
	for _, run := range trivy.Runs {
		if run.AutomationDetails == nil || run.AutomationDetails.ID != "trivy/library/nginx:1.21" {
			t.Errorf("automationDetails = %+v", run.AutomationDetails)
		}
	}
}
