package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("HCS_FAKE_KICS") == "1" {
		runFakeKICS()
		return
	}
	os.Exit(m.Run())
}

func runFakeKICS() {
	args := strings.Join(os.Args[1:], " ")
	for _, required := range []string{
		"--report-formats json,sarif",
		"--image-bom",
		"-p chart-a -p chart-b",
	} {
		if !strings.Contains(args, required) {
			fmt.Fprintln(os.Stderr, "missing arguments:", required)
			os.Exit(3)
		}
	}

	var out string
	for i, arg := range os.Args[1:] {
		if arg == "-o" && i+2 < len(os.Args) {
			out = os.Args[i+2]
			break
		}
	}
	if out == "" {
		fmt.Fprintln(os.Stderr, "missing output directory")
		os.Exit(3)
	}
	files := map[string]string{
		"results.json":        `{"severity_counters":{},"queries":[]}`,
		"results.sarif":       `{"version":"2.1.0","runs":[]}`,
		"kics-image-bom.json": `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[]}`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(out, name), []byte(content), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(3)
		}
	}
	os.Exit(0)
}

func TestKICSScan(t *testing.T) {
	kics, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HCS_FAKE_KICS", "1")
	out := t.TempDir()
	got, err := Runner{KICSBin: kics}.KICSScan([]string{"chart-a", "chart-b"}, "", out)
	if err != nil {
		t.Fatalf("KICSScan: %v", err)
	}
	if filepath.Base(got.JSON) != "results.json" ||
		filepath.Base(got.SARIF) != "results.sarif" ||
		filepath.Base(got.ImageBOM) != "kics-image-bom.json" {
		t.Errorf("outputs = %+v", got)
	}
	// The stub only writes these files if BOTH required flags were passed,
	// so their existence proves KICSScan emitted --report-formats json,sarif and --image-bom.
	for _, p := range []string{got.JSON, got.SARIF, got.ImageBOM} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected KICS to have written %s: %v", p, err)
		}
	}
}
