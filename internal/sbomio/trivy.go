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
