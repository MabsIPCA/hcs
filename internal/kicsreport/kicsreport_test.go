package kicsreport

import "testing"

func TestRead(t *testing.T) {
	r, err := Read("../../testdata/kics-results.json")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if r.Counts["critical"] != 1 || r.Counts["high"] != 2 || r.Counts["info"] != 3 {
		t.Errorf("counts = %v", r.Counts)
	}
	if len(r.Findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(r.Findings))
	}
	// most-severe first
	if r.Findings[0].Severity != "critical" || r.Findings[0].Query != "Container Running As Root" {
		t.Errorf("findings[0] = %+v", r.Findings[0])
	}
	if r.Findings[0].File != "templates/deployment.yaml" || r.Findings[0].Line != 40 {
		t.Errorf("findings[0] location = %+v", r.Findings[0])
	}
}
