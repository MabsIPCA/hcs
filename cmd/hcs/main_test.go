package main

import (
	"reflect"
	"testing"
)

func TestParseScanArgsMultiplePaths(t *testing.T) {
	paths, opts, err := parseScanArgs([]string{
		"charts/api", "--output", "results.sarif", "charts/worker", "--fail-on=high",
	})
	if err != nil {
		t.Fatalf("parseScanArgs: %v", err)
	}
	want := []string{"charts/api", "charts/worker"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
	if opts.output != "results.sarif" || opts.failOn != "high" {
		t.Fatalf("options = %+v", opts)
	}
}

func TestParseScanArgsSinglePathBackwardCompatible(t *testing.T) {
	paths, opts, err := parseScanArgs([]string{".", "--summary", "summary.md"})
	if err != nil {
		t.Fatalf("parseScanArgs: %v", err)
	}
	if !reflect.DeepEqual(paths, []string{"."}) || opts.summaryOut != "summary.md" {
		t.Fatalf("paths = %v, options = %+v", paths, opts)
	}
}

func TestParseScanArgsRequiresAPath(t *testing.T) {
	if _, _, err := parseScanArgs([]string{"--output", "results.sarif"}); err == nil {
		t.Fatal("parseScanArgs succeeded without a path")
	}
}

func TestParseScanArgsDoubleDashAllowsDashPath(t *testing.T) {
	paths, _, err := parseScanArgs([]string{"--", "-chart"})
	if err != nil {
		t.Fatalf("parseScanArgs: %v", err)
	}
	if !reflect.DeepEqual(paths, []string{"-chart"}) {
		t.Fatalf("paths = %v", paths)
	}
}
