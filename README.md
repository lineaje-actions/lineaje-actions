# Lineaje Scan Action

Scan container images and source repositories for vulnerabilities directly in GitHub Actions using [Lineaje](https://www.lineaje.com/).

The action installs the required scanner and language runtime, submits the scan, waits for analysis, and prints an Exploited, Critical, and High vulnerability summary in the job log. Optional post-scan modes can also generate patched artifacts:

- **Image scan** → patched `Dockerfile`
- **Supported source scan with `fix_plan`** → patched dependency manifest (`pom.xml`, `build.gradle`, `requirements.txt`, `package.json`, etc.)
- **Any normal `fix_plan` run** → complete fix-plan response as `raw-fix-plan.json`
- **Python or Node.js source scan with `fix_plan_gos_compat`** → Fortknox package availability and installation compatibility checks, with verified candidate manifests uploaded as artifacts

### Compatibility at a glance

| Scan target | Supported ecosystems | `scan_only` | `fix_plan` | `fix_plan_gos_compat` |
|---|---|:---:|:---:|:---:|
| Container image | Any containerized workload | ✓ | ✓ | — |
| Source repository | Java, Python, Node.js, .NET, Go, Rust | ✓ | Java, Python, Node.js, .NET, Rust | Python, Node.js |

Linux runners are required. For image scans, rebuild from the patched Dockerfile and scan the rebuilt image to verify fixes — see [Rebuild & rescan workflow](#rebuild--rescan-workflow).

---

## Table of contents

- [Prerequisites](#prerequisites)
- [Quick start](#quick-start)
- [Usage examples](#usage-examples)
- [Rebuild & rescan workflow](#rebuild--rescan-workflow)
- [Inputs](#inputs)
- [Outputs and artifacts](#outputs-and-artifacts)
- [`post_scan` modes](#post_scan-modes)
  - [`fix_plan_gos_compat`](#fix_plan_gos_compat)
- [Secrets](#secrets)
- [Private Python packages](#private-python-packages)
- [Registry authentication](#registry-authentication)
- [Supported language versions](#supported-language-versions)
- [Caching](#caching)
- [Versioning & pinning](#versioning--pinning)

---

## Prerequisites

- **Lineaje token** — get from your Lineaje account; store as a GitHub secret named `LINEAJE_CLI_TOKEN`
- **Runner** — Linux only (`ubuntu-latest` recommended). x86_64 and aarch64 supported. Windows / macOS runners are not supported.
- **Docker** — required only for image scans (pre-installed on `ubuntu-latest`)
- **Repo checkout** — the workflow must run `actions/checkout@v4` before this action so source files / Dockerfile are available

---

## Quick start

This minimal workflow builds and scans a local container image. The default `post_scan: scan_only` prints the vulnerability summary without generating a fix artifact.

```yaml
name: Lineaje scan

on:
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - run: docker build -t myapp:latest .

      - uses: lineaje-actions/lineaje-actions@v1
        with:
          scan_type: image
          image: myapp:latest
          lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
          org_name: dummy_org
```

To generate a patched Dockerfile, add `post_scan: fix_plan` and `metafiles: Dockerfile`. For source scanning, skip the Docker build and provide `scan_type: source`, `language`, and `language_version`; see the examples below.

---

## Usage examples

### Image scan — locally built image with fix plan

```yaml
- run: docker build -t myapp:latest .

- uses: lineaje-actions/lineaje-actions@v1
  with:
    scan_type: image
    image: myapp:latest
    metafiles: Dockerfile
    lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
    org_name: dummy_org
    post_scan: fix_plan
```

### Image scan — registry image with fix plan

```yaml
- uses: lineaje-actions/lineaje-actions@v1
  with:
    scan_type: image
    image: docker.io/library/python:3.8-slim
    image_source_type: registry
    metafiles: Dockerfile
    lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
    org_name: dummy_org
    post_scan: fix_plan
```

### Image scan — scan only (no fix plan, no Dockerfile needed)

```yaml
- uses: lineaje-actions/lineaje-actions@v1
  with:
    scan_type: image
    image: docker.io/library/python:3.8-slim
    image_source_type: registry
    lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
    org_name: dummy_org
    post_scan: scan_only
```

### Image scan — multiple images in one job

Use `version_prefix` to keep each image's scan distinct when scanning multiple images in the same workflow run.

```yaml
- run: docker build -t nginx-app:latest -f docker/nginx/Dockerfile .
- run: docker build -t api-app:latest -f docker/api/Dockerfile .

- uses: lineaje-actions/lineaje-actions@v1
  with:
    scan_type: image
    image: nginx-app:latest
    version_prefix: nginx
    lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
    org_name: dummy_org

- uses: lineaje-actions/lineaje-actions@v1
  with:
    scan_type: image
    image: api-app:latest
    version_prefix: api
    lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
    org_name: dummy_org
```

This produces versions `nginx-image-<run>-<attempt>` and `api-image-<run>-<attempt>` — each tracked separately in Lineaje.

### Source scan — scan only (Java 17)

```yaml
- uses: lineaje-actions/lineaje-actions@v1
  with:
    scan_type: source
    lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
    org_name: dummy_org
    language: java
    language_version: "17"
    post_scan: scan_only
```

### Source scan — scan + fix plan (uploads patched manifest)

```yaml
- uses: lineaje-actions/lineaje-actions@v1
  with:
    scan_type: source
    lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
    org_name: dummy_org
    language: python
    language_version: "3.10"
    post_scan: fix_plan
```

### Source scan — .NET

```yaml
- uses: lineaje-actions/lineaje-actions@v1
  with:
    scan_type: source
    lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
    org_name: dummy_org
    language: dotnet
    language_version: "8.0"
    post_scan: scan_only
```

### Source scan — Python project with private packages

If your `pyproject.toml` lists packages from a private registry, pass the registry URL via `pip_extra_index_url`. pip resolves private packages from that index and public packages from PyPI as normal.

```yaml
- uses: lineaje-actions/lineaje-actions@v1
  with:
    scan_type: source
    lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
    org_name: dummy_org
    language: python
    language_version: "3.12"
    pip_extra_index_url: ${{ secrets.PIP_EXTRA_INDEX_URL }}
```

Store the full URL (including credentials) as a GitHub secret:
```
https://user:token@your-registry.example.com/simple/
```

Multiple registries are supported via space separation:
```yaml
pip_extra_index_url: "${{ secrets.REGISTRY_A_URL }} ${{ secrets.REGISTRY_B_URL }}"
```

### Source scan — subdirectory (Node.js 18)

```yaml
- uses: lineaje-actions/lineaje-actions@v1
  with:
    scan_type: source
    source_dir: my-service
    lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
    org_name: dummy_org
    language: node
    language_version: "18"
    post_scan: fix_plan
```

### Source scan — Rust

```yaml
- uses: lineaje-actions/lineaje-actions@v1
  with:
    scan_type: source
    lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
    org_name: dummy_org
    language: rust
    language_version: "1.75.0"
    post_scan: scan_only
```

### Source scan — Go 1.21

```yaml
- uses: lineaje-actions/lineaje-actions@v1
  with:
    scan_type: source
    lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
    org_name: dummy_org
    language: golang
    language_version: "1.21"
    post_scan: scan_only
```

---

## Rebuild & rescan workflow

The action does **not** rebuild the patched image itself — your `docker build` may need build args, secrets, target platform, or cache settings the action cannot know. Instead, it produces the patched Dockerfile and you rebuild it yourself, then call the action again in `scan_only` mode to verify.

```yaml
jobs:
  scan-and-fix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # 1. Build the original image
      - run: docker build -t myapp:latest .

      # 2. Scan + fix plan → uploads patched Dockerfile artifact
      - name: Lineaje scan + fix plan
        id: scan
        uses: lineaje-actions/lineaje-actions@v1
        with:
          scan_type: image
          image: myapp:latest
          metafiles: Dockerfile
          lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
          org_name: dummy_org
          post_scan: fix_plan

      # 3. Fail if any Exploited + Critical + High vulnerabilities were found
      - name: Check for ECH vulnerabilities
        run: |
          ECH="${{ steps.scan.outputs.ech_count }}"
          if [ -n "$ECH" ] && [ "$ECH" -gt 0 ]; then
            echo "ERROR: $ECH Exploited/Critical/High vulnerability/vulnerabilities found"
            exit 1
          fi

      # 4. Rebuild only when curated fixes exist (already available as-is).
      #    Skip when premium_only=true — those fixes must be requested from
      #    Lineaje first and are not yet available to apply.
      - name: Build patched image
        if: steps.scan.outputs.premium_only == 'false' && steps.scan.outputs.fix_artifact_uploaded == 'true'
        run: |
          docker build \
            -f ${{ steps.scan.outputs.patched_dockerfile }} \
            --build-arg MY_BUILD_ARG=value \
            --secret id=mysecret,src=$HOME/.secret \
            -t myapp:latest-patched \
            .

      # 5. Rescan the patched image to confirm fixes
      - name: Lineaje rescan (patched)
        if: steps.scan.outputs.premium_only == 'false' && steps.scan.outputs.fix_artifact_uploaded == 'true'
        uses: lineaje-actions/lineaje-actions@v1
        with:
          scan_type: image
          image: myapp:latest-patched
          lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
          org_name: dummy_org
          post_scan: scan_only
```

---

## Inputs

### Common

| Input | Required | Default | Description |
|---|---|---|---|
| `scan_type` | **yes** | — | `image` or `source` |
| `lineaje_cli_token` | **yes** | — | Lineaje token — always use a secret |
| `org_name` | **yes** | — | Lineaje organization name |
| `project_name` | no | repository name | Lineaje project name |
| `project_version` | no | `<scan_type>-<run_number>-<run_attempt>` | Lineaje project version |
| `version_prefix` | no | _(none)_ | Short label prepended to the auto-generated version (e.g. `nginx` → `nginx-image-42-1`). Useful when scanning multiple images in one job. |
| `output_dir` | no | `/tmp/lineaje-scan-output` | Directory where scan output is written |
| `post_scan` | no | `scan_only` | `scan_only`, `fix_plan`, or `fix_plan_gos_compat`. The `fix_plan_gos_compat` mode is limited to Python and Node.js source scans. See [post_scan modes](#post_scan-modes). |
| `fast_scan` | no | `true` | Enable fast scan mode. Set to `false` for a deeper but slower scan. |
| `gos_mode` | no | `observe` | GOS premium registry mode: `observe` or `enforce` |

### Image scan inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `image` | **yes** | — | Container image reference, e.g. `docker.io/library/python:3.8-slim` |
| `metafiles` | conditional | — | Path to the Dockerfile — required when `post_scan: fix_plan` (used to generate the patched Dockerfile). Optional for `scan_only`. |
| `image_source_type` | no | `daemon` | `daemon` — image already in local Docker (e.g. just built with `docker build`) · `registry` — pull from registry first |

### Source scan inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `language` | **yes** | — | Runtime to install: `java` · `python` · `node` · `golang` · `dotnet` · `rust` |
| `language_version` | **yes** | — | Version to install (see [Supported language versions](#supported-language-versions)) |
| `source_dir` | no | `.` | Path to source directory, relative to repo root |
| `matching_ref` | no | current branch | Branch, tag, or commit being scanned |
| `pip_extra_index_url` | no | _(none)_ | Space-separated extra pip index URL(s) for resolving private Python packages (sets `PIP_EXTRA_INDEX_URL`). Embed credentials in the URL or store the whole value as a secret. See [Private Python packages](#private-python-packages). |

---

## Outputs and artifacts

| Output | Type | Description |
|---|---|---|
| `fix_artifact_uploaded` | `'true'` \| `'false'` | Whether a patched artifact was produced and uploaded. The separate raw fix-plan response does not affect this output. |
| `patched_dockerfile` | `string` | Absolute path to the patched Dockerfile on the runner (image scan + `fix_plan` only). Empty string otherwise. Use directly with `docker build -f`. |
| `ech_count` | `number` | Combined count of Exploited + Critical + High vulnerabilities. Missing or unparsable counts default to zero, so check scan warnings before treating zero as a clean result. |
| `premium_only` | `'true'` \| `'false'` | `true` when a fix plan was produced and every fix is **premium** type — fixes that must be requested from Lineaje before they become available. `false` when at least one **curated** fix exists (already available as-is and can be applied immediately by rebuilding), or when no fix plan was produced. |

Artifact contents by scan type:

| Scan type | `post_scan` | Artifact name | Files |
|---|---|---|---|
| `image` | `fix_plan` | `patched-dockerfile` | Patched `Dockerfile` |
| `source` (except Go) | `fix_plan` | `lineaje-fix-plan` | Patched dependency manifest — `pom.xml`, `build.gradle`, `build.gradle.kts`, `requirements.txt`, `Pipfile`, `pyproject.toml`, `package.json`, `package-lock.json` (whichever applies to the project) |
| image or supported source | `fix_plan` | `lineaje-raw-fix-plan` | Complete fix-plan response as `raw-fix-plan.json` |
| Python or Node.js source | `fix_plan_gos_compat` | `lineaje-fix-plan` | Fortknox-available, installation-verified candidate manifests under `<output_dir>/fix/`, with the repository layout preserved |

Normal `fix_plan` runs upload `lineaje-raw-fix-plan` whenever a fix-plan response is received, including responses with no available fixes. This artifact is not produced by `fix_plan_gos_compat`.

Treat the raw response as scan data: it can include component details, vulnerability information, and temporary artifact URLs. Access and retention follow the repository's GitHub Actions artifact settings.

Download the raw response later in the same job:

```yaml
- uses: actions/download-artifact@v4
  with:
    name: lineaje-raw-fix-plan
    path: lineaje-results

- run: jq . lineaje-results/raw-fix-plan.json
```

---

## `post_scan` modes

| Value | Scan types | What happens |
|---|---|---|
| `scan_only` | image · source | Scan only — vulnerability summary printed, no fix plan |
| `fix_plan` | image · source except Go | Scan → generate fix plan → upload the raw response and any patched artifact |
| `fix_plan_gos_compat` | Python and Node.js source only | Scan → generate fix plan → check package availability in Fortknox → verify installation compatibility → upload candidate manifests |

With `fix_plan`, image scans upload a patched `Dockerfile`; supported source scans upload a patched dependency manifest (`pom.xml`, `build.gradle`, `requirements.txt`, `package.json`, etc.).

### `fix_plan_gos_compat`

`fix_plan` provides the generated manifest from the fix plan. `fix_plan_gos_compat` checks whether its suggested packages are available in the Lineaje Fortknox Artifactory and whether the resulting Python or Node.js manifests install successfully. It does not modify the checked-out repository or apply the fixes to the project. Verified candidate manifests are uploaded with the repository layout preserved, so a monorepo's per-module manifests remain in their own subdirectories.

Because plan generation and Fortknox availability processing run asynchronously, this mode takes noticeably longer than `fix_plan`: the action waits for the fix plan, waits for candidate-manifest tasks, and then runs installation verification before uploading the results.

```yaml
- uses: lineaje-actions/lineaje-actions@v1
  with:
    scan_type: source
    lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
    org_name: dummy_org
    language: node
    language_version: "18"
    post_scan: fix_plan_gos_compat
```

Notes:

- **Python and Node.js source scans only.** Other languages and image scans fail validation up front. Use `fix_plan` for image scans and supported source ecosystems; Go supports `scan_only` only.
- **Python and Node.js candidate manifests are installation-verified before being uploaded.** Python installs discovered `requirements.txt` files in a temporary virtual environment. Node.js runs `npm install` for discovered `package.json` files using the generated GOS npm configuration and a temporary cache. Only the verifier matching the `language` input runs.
- Verified candidate manifests are written to `<output_dir>/fix/` on the runner and uploaded as the `lineaje-fix-plan` artifact. The action does not write them back into the checked-out repository.
- To consume the fixes at build time, point your package manager at the GOS registry — the rebuilt versions only resolve from there. `gos_mode` controls whether that registry is used in `observe` or `enforce` mode.

---

## Secrets

Add `LINEAJE_CLI_TOKEN` as a repository secret:
**Settings → Secrets and variables → Actions → New repository secret**

Then pass it in your workflow:
```yaml
lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
```

> **Tip:** `org_name` is not sensitive, so you can store it as a repository variable instead of hardcoding it:
> **Settings → Secrets and variables → Actions → Variables → New repository variable**
>
> Then reference it in your workflow:
> ```yaml
> org_name: ${{ vars.LINEAJE_ORG_NAME }}
> ```

---

## Private Python packages

If your `pyproject.toml` depends on packages that are not on PyPI, native dependency analysis will fail and the scan falls back to a generic filesystem scan. To avoid this, pass `pip_extra_index_url` with your private registry's [PEP 503](https://peps.python.org/pep-0503/) simple index URL.

**Store the URL as a secret** (it typically contains credentials):

```
Settings → Secrets and variables → Actions → New repository secret
Name:  PIP_EXTRA_INDEX_URL
Value: https://user:token@your-registry.example.com/simple/
```

Then reference it in your workflow:

```yaml
pip_extra_index_url: ${{ secrets.PIP_EXTRA_INDEX_URL }}
```

**Using a reusable workflow?** Thread the secret through explicitly, or use `secrets: inherit`:

```yaml
# reusable workflow definition
on:
  workflow_call:
    secrets:
      pip_extra_index_url:
        required: false
jobs:
  scan:
    steps:
      - uses: lineaje-actions/lineaje-actions@v1
        with:
          pip_extra_index_url: ${{ secrets.pip_extra_index_url }}
```

```yaml
# calling workflow
jobs:
  scan:
    uses: ./.github/workflows/reusable-scan.yml
    secrets: inherit   # passes all secrets automatically
```

---

## Registry authentication

The action does not handle registry login. Add a login step **before** calling this action if your image requires authentication:

```yaml
steps:
  - uses: actions/checkout@v4

  # Docker Hub
  - uses: docker/login-action@v3
    with:
      username: ${{ secrets.DOCKER_USERNAME }}
      password: ${{ secrets.DOCKER_PASSWORD }}

  # AWS ECR
  - uses: aws-actions/amazon-ecr-login@v2

  # Azure ACR
  - uses: azure/docker-login@v1
    with:
      login-server: myregistry.azurecr.io
      username: ${{ secrets.ACR_USERNAME }}
      password: ${{ secrets.ACR_PASSWORD }}

  - uses: lineaje-actions/lineaje-actions@v1
    with:
      scan_type: image
      image: myregistry.azurecr.io/myapp:latest
      image_source_type: registry
      lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
      org_name: dummy_org
```

---

## Supported language versions

### Java

Pass the **major version** via `language_version`. Maven and Gradle are bundled automatically.

| `language_version` | JDK |
|---|---|
| `8` | OpenJDK 8u42 |
| `9` | OpenJDK 9.0.4 |
| `10` | OpenJDK 10.0.2 |
| `11` | OpenJDK 11.0.2 |
| `12` | OpenJDK 12.0.2 |
| `13` | OpenJDK 13.0.2 |
| `14` | OpenJDK 14.0.2 |
| `15` | OpenJDK 15.0.2 |
| `16` | OpenJDK 16.0.2 |
| `17` | OpenJDK 17.0.2 |
| `18` | OpenJDK 18.0.2 |
| `19` | OpenJDK 19.0.1 |
| `20` | OpenJDK 20.0.2 |
| `21` | OpenJDK 21.0.2 (LTS) |
| `22` | OpenJDK 22.0.2 |
| `23` | OpenJDK 23.0.2 |
| `24` | OpenJDK 24.0.2 |
| `25` | OpenJDK 25.0.2 (LTS) |

**Maven:** 3.8.9 · **Gradle:** 4.9, 5.5.1, 5.6.4, 6.3, 6.9.1, 7.4.2, 7.5.1, 7.6.1, 8.0.2, 8.1.1, 8.2, 8.4, 8.6, 8.9

### Python

Pass the **minor version** via `language_version` (e.g. `3.12`).

| `language_version` | Python version |
|---|---|
| `3.6` | 3.6.15 |
| `3.7` | 3.7.15 |
| `3.8` | 3.8.15 |
| `3.9` | 3.9.15 |
| `3.10` | 3.10.8 |
| `3.11` | 3.11.8 |
| `3.12` | 3.12.9 |
| `3.13` | 3.13.3 |
| `3.14` | 3.14.5 |

### Node.js

Pass the **major version** via `language_version` (e.g. `18`).

| `language_version` | Node.js version |
|---|---|
| `16` | 16.20.2 |
| `18` | 18.19.0 |
| `20` | 20.18.0 |
| `21` | 21.4.0 |
| `22` | 22.11.0 |
| `24` | 24.15.0 |
| `26` | 26.2.0 |

### Go

Pass the **minor version** via `language_version` (e.g. `1.21`). Both module-mode and vendor-mode repositories are supported.

> **Note:** `post_scan: fix_plan` is not yet supported for Go — the action automatically falls back to `scan_only` when it is set. `fix_plan_gos_compat` supports only Python and Node.js source scans.

| `language_version` | Go version |
|---|---|
| `1.18` | 1.18.10 |
| `1.19` | 1.19.13 |
| `1.20` | 1.20.14 |
| `1.21` | 1.21.13 |
| `1.22` | 1.22.12 |
| `1.23` | 1.23.12 |
| `1.24` | 1.24.13 |
| `1.25` | 1.25.11 |
| `1.26` | 1.26.4 |

### .NET

Pass the **SDK channel** via `language_version` (e.g. `8.0`). Unlike the pinned runtimes above, .NET SDK channels resolve at action runtime.

Supported: `6.0` · `7.0` · `8.0` · `9.0` · `10.0`

### Rust

Pass a `rustup`-resolvable toolchain version via `language_version` (e.g. `1.75.0`) — there's no fixed version list, `rustup toolchain install` resolves it directly.

---

## Caching

Language runtimes are cached per `language` + `language_version` via `actions/cache`. On a cache hit the download is skipped entirely, cutting setup time to seconds.

---

## Versioning & pinning

Pick the pin that matches your tolerance for change:

| Pin | Example | Updates |
|---|---|---|
| Major | `@v1` | Auto-receives all `v1.x.y` patches and minor updates. Recommended. |
| Exact | `@v1.2.3` | Frozen — no updates until you bump it manually. |
| SHA | `@<commit-sha>` | Immutable — strongest supply-chain guarantee. |

Most users should pin to `@v1`. Switch to an exact tag or SHA when you need byte-for-byte reproducibility (e.g. compliance audits).

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
