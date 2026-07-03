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
