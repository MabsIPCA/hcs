# hcs — Unified SARIF Helm Chart Scanner

**Date:** 2026-07-05
**Status:** Approved design, pending implementation plan

## Summary

Pivot `hcs` from a *Helm Chart SBOM Scanner* (CycloneDX output) to a broader
*Helm Chart Scanner* that produces a single unified **SARIF 2.1.0** report
combining:

- **KICS** IaC/misconfiguration findings on the rendered chart (real
  `file:line` locations), and
- **Trivy** CVE vulnerabilities for every container image the chart references.

The CycloneDX SBOM output is removed. Findings surface as (a) a sticky PR
comment summary and (b) an upload to GitHub code scanning (Security tab +
inline PR annotations).

## Goals

- One unified SARIF file as the primary deliverable.
- Surface **both** engines' findings (KICS misconfig + Trivy image CVEs).
- Keep the sticky PR-comment summary; add GitHub code-scanning upload.
- Optional CI gating via `--fail-on <severity>` (report-only by default).
- Rebrand "Helm Chart SBOM Scanner" → "Helm Chart Scanner" (`hcs`, repo,
  module, and `ghcr.io/mabsipca/hcs` image name all unchanged).

## Non-goals

- No Trivy secret scanning or Trivy IaC/config scanning (the latter overlaps
  KICS). Coverage is exactly KICS misconfig + Trivy image CVEs.
- No CycloneDX SBOM output (removed).
- No change to the Docker image's bundled tools (KICS fork already supports
  `--image-bom`; SARIF is a standard KICS/Trivy format).

## Architecture & data flow

```
Helm chart
   │
   ├─► KICS (single run):
   │     kics scan -p <path> --experimental-helm-scan --image-bom \
   │       --report-formats sarif -o <tmp> --no-progress
   │       ├─ results.sarif        misconfiguration findings (file:line)
   │       └─ kics-image-bom.json  image inventory + chart provenance
   │
   ├─► for each image in kics-image-bom.json:
   │     trivy image <ref> --format sarif --scanners vuln -o <tmp>/trivy-<n>.sarif
   │
   ▼
  sarif merge:  unified SARIF, runs = [ KICS run, Trivy run per image … ]
   │
   ├─► hcs.sarif        artifact + code-scanning upload
   ├─► hcs-summary.md    sticky PR comment
   └─► exit code         0, unless --fail-on threshold crossed
```

KICS now performs image discovery **and** misconfiguration analysis in a
single invocation. Trivy remains one CVE scan per discovered image. Merging is
primarily concatenation of each source SARIF's `.runs[]` into one log; GitHub
code scanning accepts multi-run SARIF.

## Components

| Package | Change |
|---|---|
| `internal/runner` | Replace `KICSImageBOM` with `KICSScan` — adds `--report-formats sarif`; returns paths to both `results.sarif` and `kics-image-bom.json`. Replace `TrivyImageBOM` with `TrivyImageSARIF` (`--format sarif --scanners vuln`). KICS still exits non-zero when it has findings; that is not a runner error. |
| `internal/sbomio` | Keep `ReadKICSImages` (still parses `kics-image-bom.json` for image discovery + provenance). `cyclonedx-go` remains a dependency **only** for this. |
| `internal/sarif` (new) | Minimal SARIF 2.1.0 structs; `Read(path)`, `Merge(logs…) *Log`, and a tool-aware `Severity(result, rule)` normalizer → `critical/high/medium/low/info`. |
| `internal/merge` | **Removed** (CycloneDX merge deleted). |
| `internal/summary` | Reworked to render from the unified SARIF: two sections — **Misconfigurations** (count by severity + top findings with `file:line`) and **Image vulnerabilities** (per-image severity table). Ends with the existing sticky `<!-- hcs-sbom -->` marker (renamed to `<!-- hcs -->`). |
| `cmd/hcs/main.go` | New orchestration + flags + exit-code logic (below). |

### SARIF model choice

Use **lightweight internal structs** for the subset of SARIF we read/write
(`version`, `$schema`, `runs[].tool.driver.{name,rules[]}`, `runs[].results[]`
with `ruleId`, `level`, `message`, `locations`, and the properties needed for
severity). Rationale: merge is run-concatenation, and we only parse severity
for the summary and gating — a full SARIF library
(`github.com/owenrumney/go-sarif`) adds weight without clear benefit.

### Severity normalization

SARIF `level` (`error/warning/note/none`) cannot distinguish Critical vs High,
so normalization is tool-aware:

- **Trivy:** prefer `rule.properties["security-severity"]` (CVSS numeric →
  bucket), fall back to the `CRITICAL/HIGH/MEDIUM/LOW` tag in
  `rule.properties.tags`.
- **KICS:** map KICS's SARIF severity representation to the same buckets.
  *(Exact field to be confirmed against a real KICS SARIF at implementation —
  see Open items.)*

Buckets: `critical > high > medium > low > info`.

## CLI & outputs

```
hcs scan <path> [flags]
  --output    hcs.sarif        unified SARIF (was hcs-sbom.json)
  --summary   hcs-summary.md   Markdown summary (unchanged name)
  --fail-on   ""               off; e.g. "critical"/"high" → non-zero exit if
                               any finding (either engine) is >= level
  --kics-config / --trivy-config / --kics-bin / --trivy-bin /
  --kics-query-path            unchanged
```

Report outputs (`--output`, `--summary`) are always written regardless of the
`--fail-on` exit code. `--fail-on` counts findings across both engines.

## GitHub Action & example workflow

`action.yml`:

1. Run `hcs scan` via the Docker image (as today), now producing `hcs.sarif` +
   `hcs-summary.md`. New input `fail-on` (default `""`).
2. Upsert sticky PR comment — existing `actions/github-script` step, new
   summary content.
3. **New:** `github/codeql-action/upload-sarif@v3` with `sarif_file: hcs.sarif`,
   `if: always()` so findings upload even when `--fail-on` fails the scan step.
4. Upload `hcs.sarif` as an artifact (path updated).

Example workflow + README: add `security-events: write` to `permissions`
(needed for code-scanning upload). Note GitHub restricts code-scanning uploads
from forked-PR contexts; findings still upload on branch pushes.

## Testing

Unit tests:

- `internal/sarif`: merge (run concatenation + result counts), severity
  normalization for Trivy (CVSS + tags) and KICS.
- `internal/summary`: both sections render; per-image grouping; empty cases.
- `cmd/hcs` (or a small unit): `--fail-on` threshold logic (below/at/above).
- Keep `internal/sbomio` `ReadKICSImages` test.

Testdata: replace CycloneDX fixtures with a real **Trivy SARIF** (already
captured) and a real **KICS SARIF** (generated during implementation).

## Rename scope

"Helm Chart SBOM Scanner" → "Helm Chart Scanner" in README, `action.yml`
`name`/`description`, `cmd/hcs/main.go` package comment, and any Dockerfile
labels. Repo, module path (`github.com/MabsIPCA/hcs`), binary name, and image
name are unchanged. The sticky-comment marker `<!-- hcs-sbom -->` becomes
`<!-- hcs -->`.

## Open items (resolve during implementation)

1. Confirm KICS SARIF **output filename** (expected `results.sarif`) and the
   exact **severity field** by generating a real KICS SARIF from a chart.
2. Confirm Trivy image SARIF location handling — the "location" is the image
   ref, not a source line; decide whether to enrich Trivy results with chart
   provenance (which template pulled the image) from `kics-image-bom.json`, or
   defer that enrichment to a later iteration.
