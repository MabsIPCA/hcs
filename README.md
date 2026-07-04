# hcs — Helm Chart SBOM Scanner

`hcs` scans a Helm chart repository and produces a merged [CycloneDX 1.5](https://cyclonedx.org/) Software Bill of Materials (SBOM) of every container image referenced in the chart, together with a Markdown summary suitable for a GitHub PR comment.

---

## Pipeline

```
Helm chart repo
      │
      ▼
  KICS (experimental Helm render + --image-bom)
      │  discovers every image referenced in chart templates
      │  attaches chart provenance (which template/values key)
      ▼
  Trivy (trivy image --format cyclonedx)
      │  scans each image for OS + language packages and CVEs
      ▼
  merge (internal/merge)
      │  builds one CycloneDX 1.5 SBOM:
      │    • each image → a "container" component
      │    • packages nested as sub-components
      │    • vulnerabilities aggregated and rewritten with image BOM-ref
      │    • chart-provenance metadata preserved as properties
      ▼
  hcs-sbom.json   (merged SBOM)
  hcs-summary.md  (Markdown summary → PR comment)
```

---

## CLI usage

```
hcs scan <path> [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--output` | `hcs-sbom.json` | Path for the merged CycloneDX JSON output |
| `--summary` | `hcs-summary.md` | Path for the Markdown summary output |
| `--kics-config` | _(none)_ | Path to a KICS config file (tunes the KICS run) |
| `--trivy-config` | _(none)_ | Path to a Trivy config file (tunes the Trivy run) |
| `--kics-bin` | `kics` | Path/name of the KICS binary |
| `--trivy-bin` | `trivy` | Path/name of the Trivy binary |
| `--kics-query-path` | `$KICS_QUERIES_PATH` | KICS query assets directory |

**Example:**

```bash
hcs scan ./my-chart \
  --output sbom.json \
  --summary summary.md \
  --kics-config .kics.yaml \
  --trivy-config trivy.yaml
```

---

## Docker usage

The published image bundles KICS (built from `MabsIPCA/kics@feat/image-bom`, which adds `--image-bom` support) and Trivy, so no local tool installation is required.

```bash
docker run --rm \
  -v "$(pwd):/workspace" -w /workspace \
  ghcr.io/mabsipca/hcs:latest scan . \
  --output hcs-sbom.json \
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
3. Uploads `hcs-sbom.json` as a workflow artifact.

### Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Path to the repo/chart to scan |
| `kics-config` | _(none)_ | Path to a KICS config file |
| `trivy-config` | _(none)_ | Path to a Trivy config file |
| `output` | `hcs-sbom.json` | Merged SBOM output path |
| `comment` | `true` | Post/update a PR comment with the findings |

### Required permissions

The workflow must grant `pull-requests: write` so the Action can post or update the PR comment:

```yaml
permissions:
  contents: read
  pull-requests: write
```

### Example workflow

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

This workflow is also checked in at `.github/workflows/sbom.yml`.

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

**`hcs-sbom.json`** — CycloneDX 1.5 JSON SBOM:
- `metadata.component`: the scanned chart as the root component.
- `components`: one `container` component per discovered image, each containing its packages as nested sub-components.
- `vulnerabilities`: all CVEs found by Trivy, each linked to the relevant image component via `affects[].ref`.

**`hcs-summary.md`** — Markdown table of images scanned, package counts, and vulnerability severity counts; used as the PR comment body.
