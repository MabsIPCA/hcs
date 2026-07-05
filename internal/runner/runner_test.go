package runner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKICSScan(t *testing.T) {
	dir := t.TempDir()
	kics := filepath.Join(dir, "kics")
	script := `#!/bin/sh
case "$*" in
  *"--report-formats json,sarif"*"--image-bom"*) ;;
  *) echo "missing flags: $*" >&2; exit 3;;
esac
# -o value is the arg after -o
prev=""; out=""
for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
printf '{"severity_counters":{},"queries":[]}' > "$out/results.json"
printf '{"version":"2.1.0","runs":[]}' > "$out/results.sarif"
printf '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[]}' > "$out/kics-image-bom.json"
`
	if err := os.WriteFile(kics, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	got, err := Runner{KICSBin: kics}.KICSScan(".", "", out)
	if err != nil {
		t.Fatalf("KICSScan: %v", err)
	}
	if filepath.Base(got.JSON) != "results.json" ||
		filepath.Base(got.SARIF) != "results.sarif" ||
		filepath.Base(got.ImageBOM) != "kics-image-bom.json" {
		t.Errorf("outputs = %+v", got)
	}
}
