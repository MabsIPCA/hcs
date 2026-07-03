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
