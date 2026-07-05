// Command hcs scans a Helm chart and writes a unified SARIF report + summary.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/MabsIPCA/hcs/internal/kicsreport"
	"github.com/MabsIPCA/hcs/internal/runner"
	"github.com/MabsIPCA/hcs/internal/sarif"
	"github.com/MabsIPCA/hcs/internal/sbomio"
	"github.com/MabsIPCA/hcs/internal/sev"
	"github.com/MabsIPCA/hcs/internal/summary"
)

func main() {
	if len(os.Args) < 3 || os.Args[1] != "scan" {
		fmt.Fprintln(os.Stderr, "usage: hcs scan <path> [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	kicsConfig := fs.String("kics-config", "", "path to KICS config file")
	trivyConfig := fs.String("trivy-config", "", "path to Trivy config file")
	output := fs.String("output", "hcs.sarif", "unified SARIF output path")
	summaryOut := fs.String("summary", "hcs-summary.md", "Markdown summary output path")
	kicsBin := fs.String("kics-bin", "kics", "kics binary")
	trivyBin := fs.String("trivy-bin", "trivy", "trivy binary")
	queryPath := fs.String("kics-query-path", os.Getenv("KICS_QUERIES_PATH"), "KICS query assets path")
	failOn := fs.String("fail-on", "", "exit non-zero if any finding is >= this severity (critical|high|medium|low|info)")
	fs.Parse(os.Args[3:])
	scanPath := os.Args[2]

	code, err := run(scanPath, *kicsConfig, *trivyConfig, *output, *summaryOut, *failOn,
		runner.Runner{KICSBin: *kicsBin, TrivyBin: *trivyBin, KICSQueryPath: *queryPath})
	if err != nil {
		fmt.Fprintln(os.Stderr, "hcs:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func run(scanPath, kicsConfig, trivyConfig, output, summaryOut, failOn string, r runner.Runner) (int, error) {
	if failOn != "" && sev.Rank(failOn) == 0 {
		return 0, fmt.Errorf("invalid --fail-on %q (want critical, high, medium, low, or info)", failOn)
	}

	tmp, err := os.MkdirTemp("", "hcs-*")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(tmp)

	kout, err := r.KICSScan(scanPath, kicsConfig, tmp)
	if err != nil {
		return 0, fmt.Errorf("kics: %w", err)
	}
	misc, err := kicsreport.Read(kout.JSON)
	if err != nil {
		return 0, fmt.Errorf("read kics json: %w", err)
	}
	kicsSarif, err := sarif.Read(kout.SARIF)
	if err != nil {
		return 0, fmt.Errorf("read kics sarif: %w", err)
	}
	images, err := sbomio.ReadKICSImages(kout.ImageBOM)
	if err != nil {
		return 0, fmt.Errorf("read kics image-bom: %w", err)
	}

	logs := []*sarif.Log{kicsSarif}
	var imageVulns []summary.ImageVulns
	for i, img := range images {
		out := filepath.Join(tmp, fmt.Sprintf("trivy-%d.sarif", i))
		if err := r.TrivyImageSARIF(img.ScanRef(), trivyConfig, out); err != nil {
			fmt.Fprintf(os.Stderr, "hcs: warning: trivy scan of %s failed: %v\n", img.ScanRef(), err)
			imageVulns = append(imageVulns, summary.ImageVulns{Display: display(img), Source: firstSource(img), Counts: map[string]int{}})
			continue
		}
		tl, err := sarif.Read(out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "hcs: warning: reading trivy SARIF for %s failed: %v\n", img.ScanRef(), err)
			imageVulns = append(imageVulns, summary.ImageVulns{Display: display(img), Source: firstSource(img), Counts: map[string]int{}})
			continue
		}
		logs = append(logs, tl)
		imageVulns = append(imageVulns, summary.ImageVulns{
			Display: display(img), Source: firstSource(img), Counts: sarif.CountBySeverity(tl),
		})
	}

	merged := sarif.Merge(logs...)
	if err := writeJSON(output, merged); err != nil {
		return 0, err
	}
	if err := os.WriteFile(summaryOut, []byte(summary.Render(misc, imageVulns)), 0o644); err != nil {
		return 0, err
	}
	fmt.Printf("hcs: wrote %s (%d images, %d misconfig findings) and %s\n",
		output, len(images), len(misc.Findings), summaryOut)

	if failOn != "" && exceeds(misc, imageVulns, failOn) {
		fmt.Fprintf(os.Stderr, "hcs: findings at or above %q severity\n", failOn)
		return 1, nil
	}
	return 0, nil
}

func exceeds(misc *kicsreport.Report, images []summary.ImageVulns, threshold string) bool {
	for s, n := range misc.Counts {
		if n > 0 && sev.AtLeast(s, threshold) {
			return true
		}
	}
	for _, img := range images {
		for s, n := range img.Counts {
			if n > 0 && sev.AtLeast(s, threshold) {
				return true
			}
		}
	}
	return false
}

func display(img sbomio.Image) string { return img.Name + ":" + img.Version }

func firstSource(img sbomio.Image) string {
	if len(img.Sources) == 0 {
		return "-"
	}
	s := img.Sources[0]
	if s.Line > 0 {
		return fmt.Sprintf("%s:%d", s.File, s.Line)
	}
	return s.File
}

func writeJSON(path string, v any) (retErr error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); retErr == nil {
			retErr = cerr
		}
	}()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
