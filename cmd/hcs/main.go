// Command hcs scans one or more Helm chart paths and writes a unified SARIF
// report + summary.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/MabsIPCA/hcs/internal/kicsreport"
	"github.com/MabsIPCA/hcs/internal/runner"
	"github.com/MabsIPCA/hcs/internal/sarif"
	"github.com/MabsIPCA/hcs/internal/sbomio"
	"github.com/MabsIPCA/hcs/internal/sev"
	"github.com/MabsIPCA/hcs/internal/summary"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "scan" {
		printUsage()
		os.Exit(2)
	}
	scanPaths, opts, err := parseScanArgs(os.Args[2:])
	if errors.Is(err, flag.ErrHelp) {
		printUsage()
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "hcs:", err)
		printUsage()
		os.Exit(2)
	}

	code, err := run(scanPaths, opts.kicsConfig, opts.trivyConfig, opts.output, opts.summaryOut, opts.kicsResultsOut, opts.failOn,
		runner.Runner{KICSBin: opts.kicsBin, TrivyBin: opts.trivyBin, KICSQueryPath: opts.queryPath})
	if err != nil {
		fmt.Fprintln(os.Stderr, "hcs:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

type scanOptions struct {
	kicsConfig     string
	trivyConfig    string
	output         string
	summaryOut     string
	kicsResultsOut string
	kicsBin        string
	trivyBin       string
	queryPath      string
	failOn         string
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "usage: hcs scan <path> [<path> ...] [flags]")
}

// parseScanArgs permits flags anywhere in the command while retaining all
// positional arguments as scan paths. The standard flag package otherwise
// stops parsing at the first positional argument.
func parseScanArgs(args []string) ([]string, scanOptions, error) {
	var opts scanOptions
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.StringVar(&opts.kicsConfig, "kics-config", "", "path to KICS config file")
	fs.StringVar(&opts.trivyConfig, "trivy-config", "", "path to Trivy config file")
	fs.StringVar(&opts.output, "output", "hcs.sarif", "unified SARIF output path")
	fs.StringVar(&opts.summaryOut, "summary", "hcs-summary.md", "Markdown summary output path")
	fs.StringVar(&opts.kicsResultsOut, "kics-results", "kics_results.json", "native KICS JSON output path")
	fs.StringVar(&opts.kicsBin, "kics-bin", "kics", "kics binary")
	fs.StringVar(&opts.trivyBin, "trivy-bin", "trivy", "trivy binary")
	fs.StringVar(&opts.queryPath, "kics-query-path", os.Getenv("KICS_QUERIES_PATH"), "KICS query assets path")
	fs.StringVar(&opts.failOn, "fail-on", "", "exit non-zero if any finding is >= this severity (critical|high|medium|low|info)")

	flagArgs, scanPaths, err := partitionScanArgs(fs, args)
	if err != nil {
		return nil, opts, err
	}
	if err := fs.Parse(flagArgs); err != nil {
		return nil, opts, err
	}
	if len(scanPaths) == 0 {
		return nil, opts, errors.New("at least one scan path is required")
	}
	return scanPaths, opts, nil
}

func partitionScanArgs(fs *flag.FlagSet, args []string) (flagArgs, paths []string, err error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			paths = append(paths, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			paths = append(paths, arg)
			continue
		}

		name := strings.TrimLeft(arg, "-")
		if before, _, ok := strings.Cut(name, "="); ok {
			name = before
		}
		if name == "h" || name == "help" {
			return nil, nil, flag.ErrHelp
		}
		f := fs.Lookup(name)
		if f == nil {
			return nil, nil, fmt.Errorf("unknown flag %q", arg)
		}
		flagArgs = append(flagArgs, arg)
		if strings.Contains(arg, "=") {
			continue
		}
		if i+1 >= len(args) {
			return nil, nil, fmt.Errorf("flag %q requires a value", arg)
		}
		i++
		flagArgs = append(flagArgs, args[i])
	}
	return flagArgs, paths, nil
}

func run(scanPaths []string, kicsConfig, trivyConfig, output, summaryOut, kicsResultsOut, failOn string, r runner.Runner) (int, error) {
	if failOn != "" && sev.Rank(failOn) == 0 {
		return 0, fmt.Errorf("invalid --fail-on %q (want critical, high, medium, low, or info)", failOn)
	}

	tmp, err := os.MkdirTemp("", "hcs-*")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(tmp)

	kout, err := r.KICSScan(scanPaths, kicsConfig, tmp)
	if err != nil {
		return 0, fmt.Errorf("kics: %w", err)
	}
	kicsResults, err := os.ReadFile(kout.JSON)
	if err != nil {
		return 0, fmt.Errorf("read kics json: %w", err)
	}
	if err := os.WriteFile(kicsResultsOut, kicsResults, 0o644); err != nil {
		return 0, fmt.Errorf("write kics json: %w", err)
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
		// Anchor the image's CVEs to the chart file:line that references it
		// (Trivy points them at the image name, which is not a repo file), and
		// give each image its own category so same-named Trivy runs don't
		// collide in GitHub code scanning.
		file, line := relSource(img)
		sarif.Anchor(tl, file, line)
		sarif.PrefixMessages(tl, "Image `"+img.ScanRef()+"`: ")
		sarif.SetCategory(tl, "trivy/"+img.ScanRef())
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
	fmt.Printf("hcs: wrote %s (%d images, %d misconfig findings), %s, and %s\n",
		output, len(images), len(misc.Findings), summaryOut, kicsResultsOut)

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

// relSource returns the first provenance source for an image, with the file
// made relative to the working directory (== repo root under the Action) so it
// is a valid repo-relative path for both the summary and SARIF locations.
func relSource(img sbomio.Image) (string, int) {
	if len(img.Sources) == 0 {
		return "", 0
	}
	s := img.Sources[0]
	file := s.File
	if cwd, err := os.Getwd(); err == nil {
		if rel, err := filepath.Rel(cwd, file); err == nil && !strings.HasPrefix(rel, "..") {
			file = rel
		}
	}
	return file, s.Line
}

func firstSource(img sbomio.Image) string {
	file, line := relSource(img)
	if file == "" {
		return "-"
	}
	if line > 0 {
		return fmt.Sprintf("%s:%d", file, line)
	}
	return file
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
