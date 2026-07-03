package runner

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func writeFakeBin(t *testing.T, dir, name, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary test is POSIX-only")
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestKICSImageBOM(t *testing.T) {
	dir := t.TempDir()
	// fake kics: writes a minimal image bom to the -o directory
	kics := writeFakeBin(t, dir, "kics", `
out=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift;; esac; shift; done
mkdir -p "$out"
printf '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[]}' > "$out/kics-image-bom.json"
`)
	r := Runner{KICSBin: kics}
	got, err := r.KICSImageBOM(".", "", dir)
	if err != nil {
		t.Fatalf("KICSImageBOM: %v", err)
	}
	if filepath.Base(got) != "kics-image-bom.json" {
		t.Errorf("path = %q", got)
	}
	if _, err := os.Stat(got); err != nil {
		t.Errorf("output not created: %v", err)
	}
}

func TestKICSImageBOMTreatsNonZeroExitAsSuccess(t *testing.T) {
	dir := t.TempDir()
	// fake kics: writes the output file and exits 1, mimicking "KICS found issues"
	kics := writeFakeBin(t, dir, "kics", `
out=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift;; esac; shift; done
mkdir -p "$out"
printf '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[]}' > "$out/kics-image-bom.json"
exit 1
`)
	r := Runner{KICSBin: kics}
	got, err := r.KICSImageBOM(".", "", dir)
	if err != nil {
		t.Fatalf("KICSImageBOM: expected nil error on non-zero exit, got: %v", err)
	}
	if filepath.Base(got) != "kics-image-bom.json" {
		t.Errorf("path = %q, want kics-image-bom.json", got)
	}
	if _, err := os.Stat(got); err != nil {
		t.Errorf("output file not created: %v", err)
	}
}

func TestKICSImageBOMFailsOnMissingBinary(t *testing.T) {
	r := Runner{KICSBin: "/nonexistent/kics"}
	_, err := r.KICSImageBOM(".", "", t.TempDir())
	if err == nil {
		t.Fatal("expected non-nil error for missing binary, got nil")
	}
}

func TestTrivyImageBOM(t *testing.T) {
	dir := t.TempDir()
	trivy := writeFakeBin(t, dir, "trivy", `
out=""
while [ $# -gt 0 ]; do case "$1" in --output) out="$2"; shift;; esac; shift; done
printf '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","bom-ref":"p","name":"p","version":"1"}]}' > "$out"
`)
	r := Runner{TrivyBin: trivy}
	bom, err := r.TrivyImageBOM("nginx:1.21", "")
	if err != nil {
		t.Fatalf("TrivyImageBOM: %v", err)
	}
	if bom.Components == nil || len(*bom.Components) != 1 {
		t.Errorf("components = %v", bom.Components)
	}
}
