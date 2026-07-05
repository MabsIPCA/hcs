// Package runner executes the bundled kics and trivy binaries.
package runner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Runner holds binary locations and KICS query assets path.
type Runner struct {
	KICSBin       string
	TrivyBin      string
	KICSQueryPath string
}

// KICSOutputs are the files a single KICS scan writes into the output dir.
type KICSOutputs struct {
	JSON     string // results.json  (native severities)
	SARIF    string // results.sarif (for the merged report)
	ImageBOM string // kics-image-bom.json (image discovery)
}

// KICSScan runs KICS once producing JSON + SARIF findings and an image BoM.
func (r Runner) KICSScan(scanPath, kicsConfig, outDir string) (KICSOutputs, error) {
	args := []string{"scan", "-p", scanPath, "--experimental-helm-scan", "--image-bom",
		"--report-formats", "json,sarif", "-o", outDir, "--no-progress"}
	if r.KICSQueryPath != "" {
		args = append(args, "-q", r.KICSQueryPath)
	}
	if kicsConfig != "" {
		args = append(args, "--config", kicsConfig)
	}
	cmd := exec.Command(r.KICSBin, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	// KICS exits non-zero when it finds results; that is not a runner failure.
	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			return KICSOutputs{}, fmt.Errorf("kics scan: %w", err)
		}
	}
	return KICSOutputs{
		JSON:     filepath.Join(outDir, "results.json"),
		SARIF:    filepath.Join(outDir, "results.sarif"),
		ImageBOM: filepath.Join(outDir, "kics-image-bom.json"),
	}, nil
}

// TrivyImageSARIF runs `trivy image <ref> --format sarif --scanners vuln` to outPath.
func (r Runner) TrivyImageSARIF(ref, trivyConfig, outPath string) error {
	args := []string{"image", ref, "--format", "sarif", "--scanners", "vuln", "--output", outPath}
	if trivyConfig != "" {
		args = append(args, "--config", trivyConfig)
	}
	cmd := exec.Command(r.TrivyBin, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("trivy image: %w", err)
	}
	return nil
}
