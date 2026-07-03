package sbomio

import "testing"

func TestReadTrivyBOM(t *testing.T) {
	bom, err := ReadTrivyBOM("../../testdata/trivy-nginx.cdx.json")
	if err != nil {
		t.Fatalf("ReadTrivyBOM: %v", err)
	}
	if bom.Components == nil || len(*bom.Components) != 2 {
		t.Fatalf("components = %v", bom.Components)
	}
	if bom.Vulnerabilities == nil || len(*bom.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities = %v", bom.Vulnerabilities)
	}
}
