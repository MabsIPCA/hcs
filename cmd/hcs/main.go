// Command hcs scans a Helm chart/repo and writes a merged CycloneDX SBOM.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/MabsIPCA/hcs/internal/merge"
	"github.com/MabsIPCA/hcs/internal/runner"
	"github.com/MabsIPCA/hcs/internal/sbomio"
	"github.com/MabsIPCA/hcs/internal/summary"
)

func main() {
	if len(os.Args) < 3 || os.Args[1] != "scan" {
		fmt.Fprintln(os.Stderr, "usage: hcs scan <path> [flags]")
		os.Exit(2)
	}
	// Contract: hcs scan <path> [flags]  — path is os.Args[2]; flags follow it.
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	kicsConfig := fs.String("kics-config", "", "path to KICS config file")
	trivyConfig := fs.String("trivy-config", "", "path to Trivy config file")
	output := fs.String("output", "hcs-sbom.json", "merged CycloneDX output path")
	summaryOut := fs.String("summary", "hcs-summary.md", "Markdown summary output path")
	kicsBin := fs.String("kics-bin", "kics", "kics binary")
	trivyBin := fs.String("trivy-bin", "trivy", "trivy binary")
	queryPath := fs.String("kics-query-path", os.Getenv("KICS_QUERIES_PATH"), "KICS query assets path")
	fs.Parse(os.Args[3:])
	scanPath := os.Args[2]

	if err := run(scanPath, *kicsConfig, *trivyConfig, *output, *summaryOut,
		runner.Runner{KICSBin: *kicsBin, TrivyBin: *trivyBin, KICSQueryPath: *queryPath}); err != nil {
		fmt.Fprintln(os.Stderr, "hcs:", err)
		os.Exit(1)
	}
}

func run(scanPath, kicsConfig, trivyConfig, output, summaryOut string, r runner.Runner) error {
	tmp, err := os.MkdirTemp("", "hcs-kics-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	bomPath, err := r.KICSImageBOM(scanPath, kicsConfig, tmp)
	if err != nil {
		return fmt.Errorf("kics: %w", err)
	}
	images, err := sbomio.ReadKICSImages(bomPath)
	if err != nil {
		return fmt.Errorf("read kics bom: %w", err)
	}

	trivyBOMs := map[string]*cdx.BOM{}
	for _, img := range images {
		tb, err := r.TrivyImageBOM(img.ScanRef(), trivyConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "hcs: warning: trivy scan of %s failed: %v\n", img.ScanRef(), err)
			continue
		}
		trivyBOMs[img.BOMRef] = tb
	}

	merged := merge.Merge(filepath.Base(scanPath), images, trivyBOMs)

	if err := writeBOM(output, merged); err != nil {
		return err
	}
	if err := os.WriteFile(summaryOut, []byte(summary.Render(merged)), 0o644); err != nil {
		return err
	}
	fmt.Printf("hcs: wrote %s (%d images) and %s\n", output, len(images), summaryOut)
	return nil
}

func writeBOM(path string, bom *cdx.BOM) (retErr error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); retErr == nil {
			retErr = cerr
		}
	}()
	enc := cdx.NewBOMEncoder(f, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	return enc.Encode(bom)
}
