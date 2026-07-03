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
				// Record package-level deps under the image ref in the BOM deps graph
				deps = append(deps, cdx.Dependency{Ref: img.BOMRef, Dependencies: &pkgRefs})
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
