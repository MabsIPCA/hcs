// Package runner executes the bundled kics and trivy binaries.
package runner

import (
	"os"
	"os/exec"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/MabsIPCA/hcs/internal/sbomio"
)

// Runner holds binary locations and KICS query assets path.
type Runner struct {
	KICSBin       string
	TrivyBin      string
	KICSQueryPath string
}

// KICSImageBOM runs KICS (Helm render + image BoM) and returns the output path.
func (r Runner) KICSImageBOM(scanPath, kicsConfig, outDir string) (string, error) {
	args := []string{"scan", "-p", scanPath, "--experimental-helm-scan", "--image-bom", "-o", outDir, "--no-progress"}
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
			return "", err
		}
	}
	return filepath.Join(outDir, "kics-image-bom.json"), nil
}

// TrivyImageBOM runs `trivy image <ref> --format cyclonedx` and parses the BOM.
func (r Runner) TrivyImageBOM(ref, trivyConfig string) (*cdx.BOM, error) {
	tmp, err := os.CreateTemp("", "trivy-*.cdx.json")
	if err != nil {
		return nil, err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	args := []string{"image", ref, "--format", "cyclonedx", "--output", tmp.Name()}
	if trivyConfig != "" {
		args = append(args, "--config", trivyConfig)
	}
	cmd := exec.Command(r.TrivyBin, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return sbomio.ReadTrivyBOM(tmp.Name())
}
