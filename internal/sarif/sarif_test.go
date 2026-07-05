package sarif

import "testing"

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
