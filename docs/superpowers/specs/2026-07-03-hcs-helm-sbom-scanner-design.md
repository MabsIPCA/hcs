# Design: `hcs` — Helm Chart SBOM Scanner

**Date:** 2026-07-03
**Status:** Approved (pending spec review)
**Repo:** MabsIPCA/hcs (greenfield)

## Goal

A tool that, given a repository or Helm chart, produces a single merged CycloneDX
SBOM describing every container image the chart references **and** the packages
and vulnerabilities inside those images. It composes three tools:

- **KICS** (experimental Helm rendering + `--image-bom`) — discovers which images
  the chart references, with chart provenance (source file + line).
- **Trivy** — evaluates each discovered image (`trivy image --format cyclonedx`),
  yielding the image's packages and CVE findings.
- **`hcs`** (this project, Go) — orchestrates the two and merges their outputs
  into one CycloneDX document.

The tool ships as a self-contained Docker image and a GitHub Action that scans a
PR and comments the findings back onto it.

## Non-goals

- Reimplementing image/package scanning (delegated to Trivy) or Helm rendering
  and image discovery (delegated to KICS).
- Producing SPDX (CycloneDX only for this iteration).
- Resolving `:latest` to digests offline (inherited from KICS behavior).

## Pipeline

```
repo / Helm chart
      │
      ▼
(1) KICS: kics scan -p <path> --experimental-helm-scan --image-bom -o <tmp> [--config <kics-config>]
      │        → kics-image-bom.json  (CycloneDX image inventory + provenance)
      ▼
(2) parse image list  ──► for each image ref:
                          trivy image <ref> --format cyclonedx [--config <trivy-config>]
                          → per-image CycloneDX BOM (packages + vulnerabilities)
      ▼
(3) merge  → hcs-sbom.json (merged CycloneDX)  +  hcs-summary.md (human summary)
      ▼
(GitHub Action) upsert sticky PR comment from hcs-summary.md; upload SBOM artifact
```

## Components (Go)

Clean, independently testable boundaries:

| Package/unit | Responsibility | Depends on |
|--------------|----------------|------------|
| `cmd/hcs` | CLI parsing, wiring | flags, runner, sbomio, merge, summary |
| `internal/runner` | Shell out to `kics` and `trivy`; manage temp dirs | os/exec |
| `internal/sbomio` | Read KICS image BoM → `[]Image`; read Trivy per-image BOMs | cyclonedx-go |
| `internal/merge` | **Pure function:** KICS images + Trivy BOMs → merged BOM | cyclonedx-go |
| `internal/summary` | **Pure function:** merged BOM → Markdown summary | — |

`merge` and `summary` are pure (no process/IO) and hold the core logic, so they
are unit-testable in isolation.

## CLI surface

```
hcs scan <repo-or-chart-path>
  --kics-config <path>       # optional KICS config file (tunable)
  --trivy-config <path>      # optional Trivy config file (tunable)
  --output <path>            # merged CycloneDX (default: hcs-sbom.json)
  --summary <path>           # Markdown summary (default: hcs-summary.md)
  --kics-bin <path>          # override bundled kics (default: kics on PATH)
  --trivy-bin <path>         # override bundled trivy (default: trivy on PATH)
  --fail-on <severity>       # DEFERRED (not in v1): optional non-zero exit if >= severity found
```

> **Note (v1 descope):** `--fail-on` is deferred. v1 is comment/report-only; the
> merged SBOM carries all vulnerabilities and the PR comment surfaces the severity
> counts, so a CI gate can be added later without changing the output format.

## Merged SBOM format

Built with `github.com/CycloneDX/cyclonedx-go`. Structure:

- `metadata.component`: an `application` component representing the scanned
  chart/repo target.
- `components[]`: one `container` component per discovered image, carrying KICS
  provenance as `properties` (`kics:source:file`, `kics:source:line`). Each
  image component **nests** its Trivy-reported packages under `.components[]`.
- `vulnerabilities[]`: aggregated from all Trivy scans, with `affects[].ref`
  rewritten to the (namespaced) package bom-refs.
- `dependencies[]`: chart → images → packages.

**bom-ref namespacing:** package/component bom-refs from each Trivy BOM are
prefixed with a per-image key to guarantee uniqueness after merge; vulnerability
`affects` refs are rewritten consistently. Image component bom-ref = the KICS
normalized image key.

**Empty/edge cases:** if KICS finds no images, emit a valid SBOM with only the
target component (no image components) and an empty summary. If a Trivy scan for
one image fails, log a warning, record the image component without packages, and
continue (best-effort per image).

## Docker image (self-contained)

Multi-stage:

- **Stage `kics-build`:** builds KICS from source. Build ARGs
  `KICS_REPO` (default `https://github.com/MabsIPCA/kics`) and
  `KICS_REF` (default `feat/image-bom`), so the image can track upstream once the
  feature is merged. Produces the `kics` binary and copies its `assets/` (KICS
  needs `assets/queries` + `assets/libraries` at runtime).
- **Stage `hcs-build`:** builds the `hcs` Go binary.
- **Final stage** (small glibc base, e.g. debian-slim; KICS renders Helm via its
  Go library, so no `helm`/`git` CLI is needed at runtime):
  `hcs` + `kics` + KICS `assets/` + `trivy` (from the official Trivy release).
  `ENTRYPOINT ["hcs"]`. KICS is invoked with its bundled query path.

## GitHub Action + PR comment

**`action.yml` — composite action.** Inputs: `path` (default `.`),
`kics-config`, `trivy-config`, `output` (default `hcs-sbom.json`),
`comment` (bool, default `true`). Steps:

1. Run the `hcs` Docker image over `path` → `hcs-sbom.json` + `hcs-summary.md`.
2. If `comment` and the event is a pull request: **upsert a sticky PR comment**
   via `actions/github-script`, locating any prior comment by the hidden marker
   `<!-- hcs-sbom -->` and editing it in place, else creating it.
3. Upload `hcs-sbom.json` as a workflow artifact.

**`hcs-summary.md`** (produced by `internal/summary`) renders a per-image table of
vulnerability counts by severity plus chart provenance, and a collapsible
top-CVEs section, ending with the `<!-- hcs-sbom -->` marker:

```
## 🔎 HCS Helm SBOM scan

| Image | Source | Critical | High | Medium | Low |
|-------|--------|:-:|:-:|:-:|:-:|
| nginx:1.21 | templates/deploy.yaml:14 | 1 | 4 | 7 | 12 |

<details><summary>Top CVEs</summary> ... </details>
<!-- hcs-sbom -->
```

**`.github/workflows/sbom.yml`** — example workflow triggering on `pull_request`
(and `push`), with `permissions: pull-requests: write`, calling the action
against this repo.

## Error handling

- KICS or Trivy binary missing / non-executable → fail fast with a clear message.
- KICS scan failure → fatal (no images to work with).
- Per-image Trivy failure → warn and continue (partial SBOM), overall success
  (the `--fail-on` gate is deferred; see the CLI-surface note above).
- Malformed Trivy/KICS output → surfaced as an error naming the offending file.

## Testing (TDD)

- **`internal/merge`** (primary): fixtures of a KICS image BoM + two Trivy image
  BOMs → assert the merged BOM nests packages under the right image, carries KICS
  provenance properties, aggregates and rewrites vulnerability refs, and keeps all
  bom-refs unique. Edge cases: no images; one image's Trivy scan missing.
- **`internal/summary`:** merged BOM → assert table rows, per-severity counts, the
  provenance column, and the sticky marker.
- **`internal/sbomio`:** parse a KICS image BoM fixture → correct image refs;
  parse a Trivy BOM fixture → components/vulns.
- **Smoke integration** (build-tagged): if `kics`/`trivy` are on PATH, run the
  full pipeline over a tiny Helm chart fixture and assert a non-empty merged SBOM.

## Dependencies

- Go; `github.com/CycloneDX/cyclonedx-go` for CycloneDX read/build/merge.
- Runtime: `kics` (fork with `--image-bom`) + KICS assets, `trivy` — both bundled
  in the Docker image.
