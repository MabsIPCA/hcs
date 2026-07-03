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
