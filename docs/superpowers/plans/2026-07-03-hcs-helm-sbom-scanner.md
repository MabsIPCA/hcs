# hcs — Helm Chart SBOM Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `hcs`, a Go tool that scans a Helm chart/repo by running KICS (experimental Helm render + `--image-bom`) to discover images, Trivy to evaluate each image, and merges both into one CycloneDX SBOM — shipped as a Docker image and a PR-commenting GitHub Action.

**Architecture:** A Go CLI orchestrates two bundled binaries. `runner` shells out to `kics` and `trivy`; `sbomio` reads their CycloneDX; `merge` (pure) folds Trivy's per-image BOMs under KICS's provenance-rich image components; `summary` (pure) renders a Markdown report. A multi-stage Dockerfile bundles a fork-built KICS + Trivy + `hcs`. A composite Action runs the image and upserts a sticky PR comment.

**Tech Stack:** Go, `github.com/CycloneDX/cyclonedx-go` v0.11.0, Docker (multi-stage), GitHub composite action + `actions/github-script`.

## Global Constraints

- Module path: `github.com/MabsIPCA/hcs`. Go 1.22+.
- SBOM library: `github.com/CycloneDX/cyclonedx-go v0.11.0`. Output: **CycloneDX 1.5 JSON**.
- KICS is obtained by building from `KICS_REPO=https://github.com/MabsIPCA/kics` at `KICS_REF=feat/image-bom` (Docker build ARGs).
- KICS image BoM filename is fixed: `kics-image-bom.json`.
- Sticky PR comment marker: `<!-- hcs-sbom -->` (must be the last line of the summary).
- Every code task is TDD: write test → watch fail → implement → watch pass → commit.
- Commit messages end with:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`

## File Structure

```
go.mod
cmd/hcs/main.go                 # CLI: flags, orchestration
internal/sbomio/image.go        # Image model, ReadKICSImages, ScanRef
internal/sbomio/image_test.go
internal/sbomio/trivy.go        # ReadTrivyBOM
internal/sbomio/trivy_test.go
internal/merge/merge.go         # Merge(target, images, trivyBOMs) -> *cdx.BOM
internal/merge/merge_test.go
internal/summary/summary.go     # Render(*cdx.BOM) -> markdown
internal/summary/summary_test.go
internal/runner/runner.go       # KICSImageBOM, TrivyImageBOM (exec)
internal/runner/runner_test.go
Dockerfile
action.yml                      # composite action
.github/scripts/pr-comment.js   # github-script body (optional inline)
.github/workflows/sbom.yml      # example workflow
testdata/                       # fixtures (KICS BoM, Trivy BOMs, tiny chart)
README.md
```

---

### Task 1: Module scaffold + `sbomio.Image` (read KICS image BoM)

**Files:**
- Create: `go.mod`, `internal/sbomio/image.go`, `internal/sbomio/image_test.go`
- Create fixture: `testdata/kics-image-bom.json`

**Interfaces:**
- Produces:
  - `type Source struct { File string; Line int }`
  - `type Image struct { BOMRef, Name, Version, PackageURL, Registry string; Sources []Source }`
  - `func ReadKICSImages(path string) ([]Image, error)`
  - `func (i Image) ScanRef() string`

- [ ] **Step 1: Init module and add dependency**

```bash
cd /home/miguel/projects/hcs
go mod init github.com/MabsIPCA/hcs
go get github.com/CycloneDX/cyclonedx-go@v0.11.0
```

- [ ] **Step 2: Create the KICS BoM fixture** `testdata/kics-image-bom.json`

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000001",
  "version": 1,
  "metadata": { "timestamp": "2026-07-03T00:00:00Z", "tools": [{ "vendor": "Checkmarx", "name": "KICS", "version": "test" }] },
  "components": [
    { "type": "container", "bom-ref": "docker.io/library/nginx@1.21", "name": "library/nginx", "version": "1.21",
      "purl": "pkg:docker/library/nginx@1.21",
      "properties": [
        { "name": "kics:source:file", "value": "templates/deploy.yaml" }, { "name": "kics:source:line", "value": "14" }
      ] },
    { "type": "container", "bom-ref": "gcr.io/distroless/base@latest", "name": "distroless/base", "version": "latest",
      "purl": "pkg:docker/distroless/base@latest?repository_url=gcr.io",
      "properties": [ { "name": "kics:source:file", "value": "templates/base.yaml" }, { "name": "kics:source:line", "value": "3" } ] }
  ]
}
```

- [ ] **Step 3: Write the failing test** `internal/sbomio/image_test.go`

```go
package sbomio

import "testing"

func TestReadKICSImages(t *testing.T) {
	images, err := ReadKICSImages("../../testdata/kics-image-bom.json")
	if err != nil {
		t.Fatalf("ReadKICSImages: %v", err)
	}
	if len(images) != 2 {
		t.Fatalf("got %d images, want 2", len(images))
	}

	nginx := images[0]
	if nginx.Name != "library/nginx" || nginx.Version != "1.21" {
		t.Errorf("nginx = %+v", nginx)
	}
	if nginx.Registry != "" {
		t.Errorf("nginx registry = %q, want empty (docker.io)", nginx.Registry)
	}
	if len(nginx.Sources) != 1 || nginx.Sources[0].File != "templates/deploy.yaml" || nginx.Sources[0].Line != 14 {
		t.Errorf("nginx sources = %+v", nginx.Sources)
	}
	if nginx.ScanRef() != "library/nginx:1.21" {
		t.Errorf("nginx ScanRef = %q", nginx.ScanRef())
	}

	base := images[1]
	if base.Registry != "gcr.io" {
		t.Errorf("base registry = %q, want gcr.io", base.Registry)
	}
	if base.ScanRef() != "gcr.io/distroless/base:latest" {
		t.Errorf("base ScanRef = %q", base.ScanRef())
	}
}

func TestScanRefDigest(t *testing.T) {
	i := Image{Name: "library/alpine", Version: "sha256:abc"}
	if i.ScanRef() != "library/alpine@sha256:abc" {
		t.Errorf("ScanRef = %q", i.ScanRef())
	}
}
```

- [ ] **Step 4: Run test to verify it fails**

Run: `go test ./internal/sbomio/`
Expected: FAIL — `undefined: ReadKICSImages`

- [ ] **Step 5: Implement** `internal/sbomio/image.go`

```go
// Package sbomio reads the CycloneDX documents produced by KICS and Trivy.
package sbomio

import (
	"os"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Source is where KICS found an image reference.
type Source struct {
	File string
	Line int
}

// Image is a container image discovered by KICS.
type Image struct {
	BOMRef     string // KICS normalized key, e.g. "docker.io/library/nginx@1.21"
	Name       string // repository, e.g. "library/nginx"
	Version    string // tag or digest
	PackageURL string
	Registry   string // "" means docker.io
	Sources    []Source
}

// ReadKICSImages parses a KICS image BoM and returns its container components.
func ReadKICSImages(path string) ([]Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(f, cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, err
	}

	var images []Image
	if bom.Components == nil {
		return images, nil
	}
	for _, c := range *bom.Components {
		if c.Type != cdx.ComponentTypeContainer {
			continue
		}
		images = append(images, Image{
			BOMRef:     c.BOMRef,
			Name:       c.Name,
			Version:    c.Version,
			PackageURL: c.PackageURL,
			Registry:   registryFromPURL(c.PackageURL),
			Sources:    sourcesFromProps(c.Properties),
		})
	}
	return images, nil
}

// ScanRef reconstructs a Trivy-scannable reference.
func (i Image) ScanRef() string {
	ref := i.Name
	if i.Registry != "" && i.Registry != "docker.io" {
		ref = i.Registry + "/" + i.Name
	}
	if strings.HasPrefix(i.Version, "sha256:") {
		return ref + "@" + i.Version
	}
	if i.Version == "" {
		return ref
	}
	return ref + ":" + i.Version
}

func registryFromPURL(purl string) string {
	const key = "repository_url="
	idx := strings.Index(purl, key)
	if idx < 0 {
		return ""
	}
	val := purl[idx+len(key):]
	if amp := strings.IndexByte(val, '&'); amp >= 0 {
		val = val[:amp]
	}
	return val
}

func sourcesFromProps(props *[]cdx.Property) []Source {
	if props == nil {
		return nil
	}
	var sources []Source
	var cur Source
	haveFile := false
	for _, p := range *props {
		switch p.Name {
		case "kics:source:file":
			if haveFile {
				sources = append(sources, cur)
			}
			cur = Source{File: p.Value}
			haveFile = true
		case "kics:source:line":
			cur.Line, _ = strconv.Atoi(p.Value)
		}
	}
	if haveFile {
		sources = append(sources, cur)
	}
	return sources
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `go test ./internal/sbomio/`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum internal/sbomio/image.go internal/sbomio/image_test.go testdata/kics-image-bom.json
git commit -m "feat(sbomio): read KICS image BoM into Image model

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: `sbomio.ReadTrivyBOM`

**Files:**
- Create: `internal/sbomio/trivy.go`, `internal/sbomio/trivy_test.go`
- Create fixture: `testdata/trivy-nginx.cdx.json`

**Interfaces:**
- Produces: `func ReadTrivyBOM(path string) (*cdx.BOM, error)`

- [ ] **Step 1: Create fixture** `testdata/trivy-nginx.cdx.json` (a minimal Trivy-style image BOM)

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:00000000-0000-4000-8000-0000000000a1",
  "version": 1,
  "metadata": { "timestamp": "2026-07-03T00:00:00Z",
    "component": { "type": "container", "bom-ref": "trivy-img-nginx", "name": "library/nginx", "version": "1.21" } },
  "components": [
    { "type": "library", "bom-ref": "pkg:deb/debian/libc6@2.31?arch=amd64", "name": "libc6", "version": "2.31", "purl": "pkg:deb/debian/libc6@2.31?arch=amd64" },
    { "type": "library", "bom-ref": "pkg:deb/debian/openssl@1.1?arch=amd64", "name": "openssl", "version": "1.1", "purl": "pkg:deb/debian/openssl@1.1?arch=amd64" }
  ],
  "vulnerabilities": [
    { "bom-ref": "cve-1", "id": "CVE-2023-0001",
      "ratings": [ { "severity": "high" } ],
      "affects": [ { "ref": "pkg:deb/debian/openssl@1.1?arch=amd64" } ] }
  ]
}
```

- [ ] **Step 2: Write the failing test** `internal/sbomio/trivy_test.go`

```go
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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/sbomio/ -run TestReadTrivyBOM`
Expected: FAIL — `undefined: ReadTrivyBOM`

- [ ] **Step 4: Implement** `internal/sbomio/trivy.go`

```go
package sbomio

import (
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// ReadTrivyBOM parses a Trivy CycloneDX image BOM.
func ReadTrivyBOM(path string) (*cdx.BOM, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	bom := cdx.NewBOM()
	if err := cdx.NewBOMDecoder(f, cdx.BOMFileFormatJSON).Decode(bom); err != nil {
		return nil, err
	}
	return bom, nil
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/sbomio/`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/sbomio/trivy.go internal/sbomio/trivy_test.go testdata/trivy-nginx.cdx.json
git commit -m "feat(sbomio): read Trivy CycloneDX image BOM

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: `merge.Merge` — the core

**Files:**
- Create: `internal/merge/merge.go`, `internal/merge/merge_test.go`

**Interfaces:**
- Consumes: `sbomio.Image` (Task 1), `*cdx.BOM` (Task 2)
- Produces: `func Merge(target string, images []sbomio.Image, trivyBOMs map[string]*cdx.BOM) *cdx.BOM`
  - `trivyBOMs` is keyed by `Image.BOMRef`; a missing/nil value means that image was not (successfully) scanned.

- [ ] **Step 1: Write the failing test** `internal/merge/merge_test.go`

```go
package merge

import (
	"testing"

	"github.com/MabsIPCA/hcs/internal/sbomio"
	cdx "github.com/CycloneDX/cyclonedx-go"
)

func fixtureImages() []sbomio.Image {
	return []sbomio.Image{
		{BOMRef: "docker.io/library/nginx@1.21", Name: "library/nginx", Version: "1.21",
			PackageURL: "pkg:docker/library/nginx@1.21",
			Sources:    []sbomio.Source{{File: "templates/deploy.yaml", Line: 14}}},
		{BOMRef: "docker.io/library/redis@7", Name: "library/redis", Version: "7",
			PackageURL: "pkg:docker/library/redis@7"},
	}
}

func trivyBOM(pkgRef, vulnID, sev string) *cdx.BOM {
	b := cdx.NewBOM()
	b.Components = &[]cdx.Component{{Type: cdx.ComponentTypeLibrary, BOMRef: pkgRef, Name: "pkg", Version: "1"}}
	b.Vulnerabilities = &[]cdx.Vulnerability{{
		BOMRef:  vulnID,
		ID:      vulnID,
		Ratings: &[]cdx.VulnerabilityRating{{Severity: cdx.Severity(sev)}},
		Affects: &[]cdx.Affects{{Ref: pkgRef}},
	}}
	return b
}

func TestMerge_NestsPackagesUnderImages(t *testing.T) {
	images := fixtureImages()
	trivy := map[string]*cdx.BOM{
		"docker.io/library/nginx@1.21": trivyBOM("pkg:deb/openssl@1.1", "CVE-1", "high"),
		// redis intentionally missing (scan failed)
	}

	bom := Merge("mychart", images, trivy)

	if bom.Components == nil || len(*bom.Components) != 2 {
		t.Fatalf("want 2 image components, got %v", bom.Components)
	}
	nginx := (*bom.Components)[0]
	if nginx.Type != cdx.ComponentTypeContainer || nginx.BOMRef != "docker.io/library/nginx@1.21" {
		t.Fatalf("nginx component = %+v", nginx)
	}
	// packages nested under the image
	if nginx.Components == nil || len(*nginx.Components) != 1 {
		t.Fatalf("want 1 nested package, got %v", nginx.Components)
	}
	// nested package bom-ref namespaced under the image ref
	nested := (*nginx.Components)[0]
	want := "docker.io/library/nginx@1.21/pkg:deb/openssl@1.1"
	if nested.BOMRef != want {
		t.Errorf("nested bom-ref = %q, want %q", nested.BOMRef, want)
	}
	// provenance carried
	if !hasProp(nginx.Properties, "kics:source:file", "templates/deploy.yaml") {
		t.Errorf("missing provenance on nginx: %+v", nginx.Properties)
	}
	// vulnerability aggregated and its affects ref rewritten to the namespaced ref
	if bom.Vulnerabilities == nil || len(*bom.Vulnerabilities) != 1 {
		t.Fatalf("want 1 vulnerability, got %v", bom.Vulnerabilities)
	}
	v := (*bom.Vulnerabilities)[0]
	if (*v.Affects)[0].Ref != want {
		t.Errorf("vuln affects ref = %q, want %q", (*v.Affects)[0].Ref, want)
	}
	// redis has no packages but still appears
	redis := (*bom.Components)[1]
	if redis.BOMRef != "docker.io/library/redis@7" || redis.Components != nil {
		t.Errorf("redis = %+v", redis)
	}
	// metadata target component
	if bom.Metadata == nil || bom.Metadata.Component == nil || bom.Metadata.Component.Name != "mychart" {
		t.Errorf("metadata component = %+v", bom.Metadata)
	}
}

func hasProp(props *[]cdx.Property, name, value string) bool {
	if props == nil {
		return false
	}
	for _, p := range *props {
		if p.Name == name && p.Value == value {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/merge/`
Expected: FAIL — `undefined: Merge`

- [ ] **Step 3: Implement** `internal/merge/merge.go`

```go
// Package merge combines a KICS image inventory with per-image Trivy BOMs
// into a single CycloneDX document.
package merge

import (
	"strconv"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/MabsIPCA/hcs/internal/sbomio"
	"github.com/google/uuid"
)

// Merge folds each image's Trivy BOM (keyed by Image.BOMRef) under a container
// component for that image, carrying KICS provenance, aggregating and rewriting
// vulnerabilities, and recording a dependency graph.
func Merge(target string, images []sbomio.Image, trivyBOMs map[string]*cdx.BOM) *cdx.BOM {
	root := cdx.NewBOM()
	root.SerialNumber = "urn:uuid:" + uuid.NewString()
	root.Version = 1
	targetRef := "target:" + target
	root.Metadata = &cdx.Metadata{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Component: &cdx.Component{Type: cdx.ComponentTypeApplication, BOMRef: targetRef, Name: target},
	}

	var components []cdx.Component
	var vulns []cdx.Vulnerability
	deps := []cdx.Dependency{{Ref: targetRef, Dependencies: &[]string{}}}

	for _, img := range images {
		imgComp := cdx.Component{
			Type:       cdx.ComponentTypeContainer,
			BOMRef:     img.BOMRef,
			Name:       img.Name,
			Version:    img.Version,
			PackageURL: img.PackageURL,
			Properties: provenance(img.Sources),
		}
		addDep(&deps, targetRef, img.BOMRef)

		if tb := trivyBOMs[img.BOMRef]; tb != nil {
			prefix := img.BOMRef + "/"
			remap := map[string]string{}
			if tb.Metadata != nil && tb.Metadata.Component != nil {
				remap[tb.Metadata.Component.BOMRef] = img.BOMRef
			}

			var nested []cdx.Component
			var pkgRefs []string
			if tb.Components != nil {
				for _, c := range *tb.Components {
					newRef := prefix + c.BOMRef
					remap[c.BOMRef] = newRef
					c.BOMRef = newRef
					nested = append(nested, c)
					pkgRefs = append(pkgRefs, newRef)
				}
			}
			if len(nested) > 0 {
				imgComp.Components = &nested
				imgComp.Dependencies = &pkgRefs
			}

			if tb.Vulnerabilities != nil {
				for _, v := range *tb.Vulnerabilities {
					if v.BOMRef != "" {
						v.BOMRef = prefix + v.BOMRef
					}
					if v.Affects != nil {
						rewritten := make([]cdx.Affects, 0, len(*v.Affects))
						for _, a := range *v.Affects {
							if nr, ok := remap[a.Ref]; ok {
								a.Ref = nr
							}
							rewritten = append(rewritten, a)
						}
						v.Affects = &rewritten
					}
					vulns = append(vulns, v)
				}
			}
		}
		components = append(components, imgComp)
	}

	root.Components = &components
	if len(vulns) > 0 {
		root.Vulnerabilities = &vulns
	}
	root.Dependencies = &deps
	return root
}

func provenance(sources []sbomio.Source) *[]cdx.Property {
	if len(sources) == 0 {
		return nil
	}
	props := make([]cdx.Property, 0, len(sources)*2)
	for _, s := range sources {
		props = append(props,
			cdx.Property{Name: "kics:source:file", Value: s.File},
			cdx.Property{Name: "kics:source:line", Value: strconv.Itoa(s.Line)},
		)
	}
	return &props
}

func addDep(deps *[]cdx.Dependency, from, to string) {
	for i := range *deps {
		if (*deps)[i].Ref == from {
			d := (*deps)[i].Dependencies
			list := append(*d, to)
			(*deps)[i].Dependencies = &list
			return
		}
	}
	*deps = append(*deps, cdx.Dependency{Ref: from, Dependencies: &[]string{to}})
}
```

- [ ] **Step 4: Add uuid dependency and run tests**

```bash
go get github.com/google/uuid@latest
go test ./internal/merge/
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/merge/ go.mod go.sum
git commit -m "feat(merge): nest Trivy packages/vulns under KICS image components

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: `summary.Render` — Markdown report

**Files:**
- Create: `internal/summary/summary.go`, `internal/summary/summary_test.go`

**Interfaces:**
- Consumes: `*cdx.BOM` (merged, from Task 3)
- Produces: `func Render(bom *cdx.BOM) string`

- [ ] **Step 1: Write the failing test** `internal/summary/summary_test.go`

```go
package summary

import (
	"strings"
	"testing"

	"github.com/MabsIPCA/hcs/internal/merge"
	"github.com/MabsIPCA/hcs/internal/sbomio"
	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestRender(t *testing.T) {
	images := []sbomio.Image{{
		BOMRef: "docker.io/library/nginx@1.21", Name: "library/nginx", Version: "1.21",
		Sources: []sbomio.Source{{File: "templates/deploy.yaml", Line: 14}},
	}}
	tb := cdx.NewBOM()
	tb.Components = &[]cdx.Component{{Type: cdx.ComponentTypeLibrary, BOMRef: "pkg:deb/openssl@1.1", Name: "openssl", Version: "1.1"}}
	tb.Vulnerabilities = &[]cdx.Vulnerability{{
		BOMRef: "CVE-9", ID: "CVE-2023-9999",
		Ratings: &[]cdx.VulnerabilityRating{{Severity: cdx.SeverityHigh}},
		Affects: &[]cdx.Affects{{Ref: "pkg:deb/openssl@1.1"}},
	}}
	bom := merge.Merge("mychart", images, map[string]*cdx.BOM{"docker.io/library/nginx@1.21": tb})

	md := Render(bom)

	for _, want := range []string{
		"HCS Helm SBOM scan",
		"library/nginx:1.21",
		"templates/deploy.yaml:14",
		"CVE-2023-9999",
		"<!-- hcs-sbom -->",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("summary missing %q\n---\n%s", want, md)
		}
	}
	if !strings.HasSuffix(strings.TrimSpace(md), "<!-- hcs-sbom -->") {
		t.Errorf("marker must be last line")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/summary/`
Expected: FAIL — `undefined: Render`

- [ ] **Step 3: Implement** `internal/summary/summary.go`

```go
// Package summary renders a merged CycloneDX BOM as a Markdown PR comment.
package summary

import (
	"fmt"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

const marker = "<!-- hcs-sbom -->"

type counts struct{ critical, high, medium, low int }

// Render produces the Markdown summary, ending with the sticky marker.
func Render(bom *cdx.BOM) string {
	// Map every component bom-ref to its owning image bom-ref.
	owner := map[string]string{}
	displayRef := map[string]string{}   // image bom-ref -> "name:version"
	source := map[string]string{}       // image bom-ref -> "file:line"
	order := []string{}

	if bom.Components != nil {
		for _, img := range *bom.Components {
			order = append(order, img.BOMRef)
			owner[img.BOMRef] = img.BOMRef
			displayRef[img.BOMRef] = img.Name + ":" + img.Version
			source[img.BOMRef] = firstSource(img.Properties)
			if img.Components != nil {
				for _, p := range *img.Components {
					owner[p.BOMRef] = img.BOMRef
				}
			}
		}
	}

	perImage := map[string]*counts{}
	type cve struct{ image, id, sev string }
	var cves []cve
	if bom.Vulnerabilities != nil {
		for _, v := range *bom.Vulnerabilities {
			sev := highestSeverity(v.Ratings)
			imgRef := ""
			if v.Affects != nil {
				for _, a := range *v.Affects {
					if o, ok := owner[a.Ref]; ok {
						imgRef = o
						break
					}
				}
			}
			if imgRef == "" {
				continue
			}
			if perImage[imgRef] == nil {
				perImage[imgRef] = &counts{}
			}
			bump(perImage[imgRef], sev)
			cves = append(cves, cve{image: displayRef[imgRef], id: v.ID, sev: sev})
		}
	}

	var b strings.Builder
	b.WriteString("## 🔎 HCS Helm SBOM scan\n\n")
	b.WriteString("| Image | Source | Critical | High | Medium | Low |\n")
	b.WriteString("|-------|--------|:-:|:-:|:-:|:-:|\n")
	for _, ref := range order {
		c := perImage[ref]
		if c == nil {
			c = &counts{}
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %d | %d | %d | %d |\n",
			displayRef[ref], source[ref], c.critical, c.high, c.medium, c.low))
	}

	if len(cves) > 0 {
		sort.Slice(cves, func(i, j int) bool { return sevRank(cves[i].sev) > sevRank(cves[j].sev) })
		b.WriteString("\n<details><summary>Top CVEs</summary>\n\n")
		limit := len(cves)
		if limit > 20 {
			limit = 20
		}
		for _, c := range cves[:limit] {
			b.WriteString(fmt.Sprintf("- **%s** `%s` in `%s`\n", strings.ToUpper(c.sev), c.id, c.image))
		}
		b.WriteString("\n</details>\n")
	}

	b.WriteString("\n" + marker)
	return b.String()
}

func firstSource(props *[]cdx.Property) string {
	if props == nil {
		return "-"
	}
	file, line := "", ""
	for _, p := range *props {
		if p.Name == "kics:source:file" && file == "" {
			file = p.Value
		}
		if p.Name == "kics:source:line" && line == "" {
			line = p.Value
		}
	}
	if file == "" {
		return "-"
	}
	if line == "" {
		return file
	}
	return file + ":" + line
}

func highestSeverity(ratings *[]cdx.VulnerabilityRating) string {
	best := "low"
	if ratings == nil {
		return best
	}
	for _, r := range *ratings {
		s := strings.ToLower(string(r.Severity))
		if sevRank(s) > sevRank(best) {
			best = s
		}
	}
	return best
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func bump(c *counts, sev string) {
	switch sev {
	case "critical":
		c.critical++
	case "high":
		c.high++
	case "medium":
		c.medium++
	default:
		c.low++
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/summary/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/summary/
git commit -m "feat(summary): render merged SBOM as sticky PR-comment markdown

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: `runner` — shell out to KICS and Trivy

**Files:**
- Create: `internal/runner/runner.go`, `internal/runner/runner_test.go`

**Interfaces:**
- Produces:
  - `type Runner struct { KICSBin, TrivyBin, KICSQueryPath string }`
  - `func (r Runner) KICSImageBOM(scanPath, kicsConfig, outDir string) (string, error)`
  - `func (r Runner) TrivyImageBOM(ref, trivyConfig string) (*cdx.BOM, error)`

- [ ] **Step 1: Write the failing test** `internal/runner/runner_test.go` (uses fake binaries — shell scripts written to a temp dir)

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/runner/`
Expected: FAIL — `undefined: Runner`

- [ ] **Step 3: Implement** `internal/runner/runner.go`

```go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/runner/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/runner/
git commit -m "feat(runner): exec kics image-bom and trivy image scans

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: `cmd/hcs` — CLI wiring

**Files:**
- Create: `cmd/hcs/main.go`

**Interfaces:**
- Consumes all four internal packages.

- [ ] **Step 1: Implement** `cmd/hcs/main.go`

```go
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
	if len(os.Args) < 2 || os.Args[1] != "scan" {
		fmt.Fprintln(os.Stderr, "usage: hcs scan <path> [flags]")
		os.Exit(2)
	}
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

func writeBOM(path string, bom *cdx.BOM) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := cdx.NewBOMEncoder(f, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	return enc.Encode(bom)
}
```

- [ ] **Step 2: Build and smoke-run with fake binaries**

```bash
go build ./...
# quick manual smoke (optional): create fake kics/trivy on PATH like the runner tests, then:
# ./hcs scan ./testchart --kics-bin ... --trivy-bin ...
```
Expected: builds cleanly.

- [ ] **Step 3: Commit**

```bash
git add cmd/hcs/main.go
git commit -m "feat(cmd): wire hcs scan pipeline end to end

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: Dockerfile (self-contained image)

**Files:**
- Create: `Dockerfile`, `.dockerignore`

- [ ] **Step 1: Create** `Dockerfile`

```dockerfile
# syntax=docker/dockerfile:1

# --- Build KICS (fork with --image-bom) ---
ARG KICS_REPO=https://github.com/MabsIPCA/kics
ARG KICS_REF=feat/image-bom
FROM golang:1.26-bookworm AS kics-build
ARG KICS_REPO
ARG KICS_REF
RUN git clone --depth 1 --branch "${KICS_REF}" "${KICS_REPO}" /kics
WORKDIR /kics
RUN CGO_ENABLED=0 go build -o /out/kics ./cmd/console
# KICS needs its query + library assets at runtime
RUN cp -r assets /out/assets

# --- Build hcs ---
FROM golang:1.26-bookworm AS hcs-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/hcs ./cmd/hcs

# --- Trivy binary ---
FROM aquasec/trivy:latest AS trivy

# --- Final image ---
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git && rm -rf /var/lib/apt/lists/*
COPY --from=kics-build /out/kics /usr/local/bin/kics
COPY --from=kics-build /out/assets /opt/kics/assets
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=hcs-build /out/hcs /usr/local/bin/hcs
ENV KICS_QUERIES_PATH=/opt/kics/assets/queries
ENTRYPOINT ["hcs"]
```

- [ ] **Step 2: Create** `.dockerignore`

```
.git
*.md
testdata/*.json
```

- [ ] **Step 3: Build the image**

```bash
docker build -t hcs:dev .
```
Expected: image builds; `docker run --rm hcs:dev scan --help`-style invocation reaches `hcs`.

- [ ] **Step 4: Commit**

```bash
git add Dockerfile .dockerignore
git commit -m "build: self-contained Docker image (fork KICS + Trivy + hcs)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 8: GitHub composite Action + PR comment

**Files:**
- Create: `action.yml`

- [ ] **Step 1: Create** `action.yml`

```yaml
name: "HCS Helm SBOM Scanner"
description: "Scan a Helm chart with KICS + Trivy and comment the merged SBOM findings on the PR"
inputs:
  path:
    description: "Path to the repo/chart to scan"
    default: "."
  kics-config:
    description: "Path to a KICS config file"
    default: ""
  trivy-config:
    description: "Path to a Trivy config file"
    default: ""
  output:
    description: "Merged SBOM output path"
    default: "hcs-sbom.json"
  comment:
    description: "Post the findings as a PR comment"
    default: "true"
runs:
  using: "composite"
  steps:
    - name: Run HCS scan
      shell: bash
      run: |
        docker run --rm \
          -v "${{ github.workspace }}:/workspace" -w /workspace \
          ghcr.io/mabsipca/hcs:latest scan "${{ inputs.path }}" \
          --output "${{ inputs.output }}" --summary "hcs-summary.md" \
          ${{ inputs.kics-config && format('--kics-config {0}', inputs.kics-config) || '' }} \
          ${{ inputs.trivy-config && format('--trivy-config {0}', inputs.trivy-config) || '' }}
    - name: Upsert PR comment
      if: ${{ inputs.comment == 'true' && github.event_name == 'pull_request' }}
      uses: actions/github-script@v7
      with:
        script: |
          const fs = require('fs');
          const body = fs.readFileSync('hcs-summary.md', 'utf8');
          const marker = '<!-- hcs-sbom -->';
          const {owner, repo} = context.repo;
          const issue_number = context.payload.pull_request.number;
          const {data: comments} = await github.rest.issues.listComments({owner, repo, issue_number});
          const existing = comments.find(c => c.body && c.body.includes(marker));
          if (existing) {
            await github.rest.issues.updateComment({owner, repo, comment_id: existing.id, body});
          } else {
            await github.rest.issues.createComment({owner, repo, issue_number, body});
          }
    - name: Upload SBOM artifact
      uses: actions/upload-artifact@v4
      with:
        name: hcs-sbom
        path: ${{ inputs.output }}
```

- [ ] **Step 2: Commit**

```bash
git add action.yml
git commit -m "ci: composite action that scans and upserts a sticky PR comment

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 9: Example workflow + README

**Files:**
- Create: `.github/workflows/sbom.yml`, `README.md`

- [ ] **Step 1: Create** `.github/workflows/sbom.yml`

```yaml
name: Helm SBOM
on:
  pull_request:
  push:
    branches: [master, main]
permissions:
  contents: read
  pull-requests: write
jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: HCS scan
        uses: ./
        with:
          path: "."
          # kics-config: ".kics.yaml"
          # trivy-config: "trivy.yaml"
```

- [ ] **Step 2: Create** `README.md` (usage: CLI, Docker, Action, config tuning, output format). Include the pipeline diagram and the `--kics-config` / `--trivy-config` tuning notes.

- [ ] **Step 3: Run the full test suite and vet**

```bash
go test ./... && go vet ./...
```
Expected: all PASS, vet clean.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/sbom.yml README.md
git commit -m "docs: example workflow and README

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- KICS experimental Helm + image BoM → Task 5 (`KICSImageBOM`) + Task 6.
- Trivy per-image evaluation → Task 5 (`TrivyImageBOM`) + Task 6.
- Merge SBOMs (nested, provenance, vulns rewritten, deps) → Task 3.
- Markdown summary → Task 4.
- Tunable KICS/Trivy config paths → Task 6 flags, Task 8 inputs.
- Docker image (fork KICS + Trivy, ARG-tunable ref) → Task 7.
- GitHub Action scan + PR comment → Task 8; example workflow → Task 9.
- Testing (TDD core, smoke) → Tasks 1–5.

**Placeholder scan:** README body (Task 9 Step 2) is described, not templated — acceptable as prose deliverable; all code steps contain full code.

**Type consistency:** `Image`/`Source` (Task 1) used identically in Tasks 3–6; `Runner` methods (Task 5) match `cmd` calls (Task 6); `Merge`/`Render` signatures consistent across tasks and tests.
