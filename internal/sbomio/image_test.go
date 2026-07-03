package sbomio

import "testing"

func TestReadKICSImages(t *testing.T) {
	images, err := ReadKICSImages("../../testdata/kics-image-bom.json")
	if err != nil {
		t.Fatalf("ReadKICSImages: %v", err)
	}
	if len(images) != 3 {
		t.Fatalf("got %d images, want 3", len(images))
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

	redis := images[2]
	if redis.Name != "library/redis" || redis.Version != "7" {
		t.Errorf("redis = %+v", redis)
	}
	if len(redis.Sources) != 2 {
		t.Fatalf("redis sources: got %d, want 2", len(redis.Sources))
	}
	if redis.Sources[0].File != "templates/redis.yaml" || redis.Sources[0].Line != 9 {
		t.Errorf("redis sources[0] = %+v, want {templates/redis.yaml 9}", redis.Sources[0])
	}
	if redis.Sources[1].File != "docker-compose.yml" || redis.Sources[1].Line != 5 {
		t.Errorf("redis sources[1] = %+v, want {docker-compose.yml 5}", redis.Sources[1])
	}
}

func TestScanRefDigest(t *testing.T) {
	i := Image{Name: "library/alpine", Version: "sha256:abc"}
	if i.ScanRef() != "library/alpine@sha256:abc" {
		t.Errorf("ScanRef = %q", i.ScanRef())
	}
}
