# hcs — Helm Chart Scanner

`hcs` scans a Helm chart repository and produces a unified [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) report combining Helm misconfiguration findings and container image vulnerabilities for every image referenced in the chart, together with a Markdown summary suitable for a GitHub PR comment.

---

## Pipeline

```
Helm chart repo
      │
      ▼
  KICS (experimental Helm render + --image-bom)
      │  discovers every image referenced in chart templates
      │  emits misconfiguration findings as SARIF
      │  attaches chart provenance (which template/values key)
      ▼
  Trivy (trivy image --format sarif)
      │  scans each image for OS + language packages and CVEs, as SARIF
      ▼
  merge (internal/sarif)
      │  merges the KICS run and every Trivy run into one SARIF 2.1.0 log
      ▼
  hcs.sarif       (unified SARIF: misconfigs + image CVEs)
  hcs-summary.md  (Markdown summary → PR comment)
```

---

## CLI usage

```
hcs scan <path> [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--output` | `hcs.sarif` | Path for the unified SARIF output |
| `--summary` | `hcs-summary.md` | Path for the Markdown summary output |
| `--fail-on` | _(none)_ | Exit non-zero if any finding is at or above this severity (`critical`, `high`, `medium`, `low`, `info`) |
| `--kics-config` | _(none)_ | Path to a KICS config file (tunes the KICS run) |
| `--trivy-config` | _(none)_ | Path to a Trivy config file (tunes the Trivy run) |
| `--kics-bin` | `kics` | Path/name of the KICS binary |
| `--trivy-bin` | `trivy` | Path/name of the Trivy binary |
| `--kics-query-path` | `$KICS_QUERIES_PATH` | KICS query assets directory |

**Example:**

```bash
hcs scan ./my-chart \
  --output hcs.sarif \
  --summary summary.md \
  --fail-on high \
  --kics-config .kics.yaml \
  --trivy-config trivy.yaml
```

With `--fail-on high`, `hcs` exits `1` if any misconfiguration or image vulnerability is `high` or `critical` severity — useful for gating a CI job while still writing the SARIF/summary output for inspection.

---

## Docker usage

The image is published to `ghcr.io/mabsipca/hcs` by `.github/workflows/publish.yml` on every `v*` tag push. Consumers should reference a pinned version tag (e.g. `ghcr.io/mabsipca/hcs:v1.2.3`) rather than `latest`.

The published image bundles KICS (built from `MabsIPCA/kics@feat/image-bom`, which adds `--image-bom` support) and Trivy, so no local tool installation is required.

```bash
docker run --rm \
  -v "$(pwd):/workspace" -w /workspace \
  ghcr.io/mabsipca/hcs:latest scan . \
  --output hcs.sarif \
  --summary hcs-summary.md
```

Pass config files:

```bash
docker run --rm \
  -v "$(pwd):/workspace" -w /workspace \
  ghcr.io/mabsipca/hcs:latest scan . \
  --kics-config .kics.yaml \
  --trivy-config trivy.yaml
```

### Building the image locally

```bash
docker build -t hcs .
# Override the KICS fork/branch if needed:
docker build \
  --build-arg KICS_REPO=https://github.com/MabsIPCA/kics \
  --build-arg KICS_REF=feat/image-bom \
  -t hcs .
```

---

## GitHub Action usage

The repository ships a composite Action (`action.yml`) that:

1. Runs `hcs scan` via the Docker image.
2. On pull requests: **upserts a sticky comment** (identified by an HTML marker) with the Markdown summary — the same comment is updated on every new commit to the PR, keeping the thread tidy.
3. Uploads `hcs.sarif` to GitHub code scanning (`github/codeql-action/upload-sarif@v3`), so findings show up under the repository's **Security → Code scanning** tab.
4. Uploads `hcs.sarif` as a workflow artifact.

### Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Path to the repo/chart to scan |
| `kics-config` | _(none)_ | Path to a KICS config file |
| `trivy-config` | _(none)_ | Path to a Trivy config file |
| `output` | `hcs.sarif` | Unified SARIF output path |
| `fail-on` | _(none)_ | Exit non-zero if any finding is at or above this severity (`critical`, `high`, `medium`, `low`, `info`) |
| `comment` | `true` | Post/update a PR comment with the findings |

### Required permissions

The workflow must grant `pull-requests: write` so the Action can post or update the PR comment, and `security-events: write` so it can upload the SARIF results to code scanning:

```yaml
permissions:
  contents: read
  pull-requests: write
  security-events: write
```

### Example workflow

```yaml
name: Helm Chart Scan
on:
  pull_request:
  push:
    branches: [master, main]
permissions:
  contents: read
  pull-requests: write
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: HCS scan
        uses: ./
        with:
          path: "."
          # fail-on: "high"
          # kics-config: ".kics.yaml"
          # trivy-config: "trivy.yaml"
```

This workflow is also checked in at `.github/workflows/scan.yml`.

---

## Config tuning

### KICS (`--kics-config` / `kics-config` input)

Pass a KICS YAML config file to control which query categories to enable/disable, severity filters, exclusions, and other KICS options. The file is forwarded verbatim to the KICS `--config` flag.

Example `.kics.yaml`:

```yaml
exclude-severities:
  - info
exclude-paths:
  - "charts/vendor"
```

### Trivy (`--trivy-config` / `trivy-config` input)

Pass a Trivy YAML config file to tune vulnerability filtering, ignored CVEs, severity thresholds, and other Trivy options. The file is forwarded verbatim to the Trivy `--config` flag.

Example `trivy.yaml`:

```yaml
severity:
  - CRITICAL
  - HIGH
ignore-unfixed: true
```

---

## Output format

**`hcs.sarif`** — a unified [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) log combining every run:
- KICS Helm misconfiguration findings.
- One Trivy vulnerability run per container image discovered in the chart.
- Consumable directly by GitHub code scanning, `sarif-tools`, and other SARIF viewers.

**`hcs-summary.md`** — Markdown summary with a misconfiguration severity table and an image-by-image vulnerability severity table; used as the PR comment body.
