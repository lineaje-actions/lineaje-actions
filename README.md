# Lineaje Scan Action

Scan container images and source code for vulnerabilities using [Lineaje](https://www.lineaje.com/).

Every run prints a vulnerability summary. With `post_scan: fix_plan`, the action also generates a fix plan and uploads the patched artifact to the workflow run:

- **Image scan** → patched `Dockerfile`
- **Source scan** → patched dependency manifest (`pom.xml`, `build.gradle`, `requirements.txt`, `package.json`, etc.)

For image scans, rebuild from the patched Dockerfile and re-invoke the action in `scan_only` mode to verify fixes — see [Rebuild & rescan workflow](#rebuild--rescan-workflow).

---

## Table of contents

- [Prerequisites](#prerequisites)
- [Quick start](#quick-start)
- [Usage examples](#usage-examples)
  - [Multiple images in one job](#image-scan--multiple-images-in-one-job)
  - [Source scan — .NET](#source-scan--net)
- [Rebuild & rescan workflow](#rebuild--rescan-workflow)
- [Inputs](#inputs)
- [Outputs](#outputs)
- [`post_scan` modes](#post_scan-modes)
- [Secrets](#secrets)
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

```yaml
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
          metafiles: Dockerfile
          lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
```

---

## Usage examples

### Image scan — customer-built image (daemon mode, default)

```yaml
- run: docker build -t myapp:latest .

- uses: lineaje-actions/lineaje-actions@v1
  with:
    scan_type: image
    image: myapp:latest
    metafiles: Dockerfile
    lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
```

### Image scan — pull from registry first

```yaml
- uses: lineaje-actions/lineaje-actions@v1
  with:
    scan_type: image
    image: docker.io/library/python:3.8-slim
    image_source_type: registry
    metafiles: Dockerfile
    lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
```

### Image scan — scan only (no fix plan, no Dockerfile needed)

```yaml
- uses: lineaje-actions/lineaje-actions@v1
  with:
    scan_type: image
    image: docker.io/library/python:3.8-slim
    image_source_type: registry
    lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
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
    metafiles: docker/nginx/Dockerfile
    lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}

- uses: lineaje-actions/lineaje-actions@v1
  with:
    scan_type: image
    image: api-app:latest
    version_prefix: api
    metafiles: docker/api/Dockerfile
    lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
```

This produces versions `nginx-image-<run>-<attempt>` and `api-image-<run>-<attempt>` — each tracked separately in Lineaje.

### Source scan — scan only (Java 17)

```yaml
- uses: lineaje-actions/lineaje-actions@v1
  with:
    scan_type: source
    lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
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
    language: dotnet
    language_version: "8.0"
    post_scan: scan_only
```

### Source scan — subdirectory (Node.js 18)

```yaml
- uses: lineaje-actions/lineaje-actions@v1
  with:
    scan_type: source
    source_dir: my-service
    lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
    language: node
    language_version: "18"
    post_scan: fix_plan
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
          post_scan: fix_plan

      # 3. If a patched Dockerfile was produced, build it
      - name: Build patched image
        if: steps.scan.outputs.fix_artifact_uploaded == 'true'
        run: |
          docker build \
            -f ${{ steps.scan.outputs.patched_dockerfile }} \
            --build-arg MY_BUILD_ARG=value \
            --secret id=mysecret,src=$HOME/.secret \
            -t myapp:latest-patched \
            .

      # 4. Rescan the patched image to confirm fixes
      - name: Lineaje rescan (patched)
        if: steps.scan.outputs.fix_artifact_uploaded == 'true'
        uses: lineaje-actions/lineaje-actions@v1
        with:
          scan_type: image
          image: myapp:latest-patched
          metafiles: Dockerfile
          lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
          post_scan: scan_only
```

---

## Inputs

### Common

| Input | Required | Default | Description |
|---|---|---|---|
| `scan_type` | **yes** | — | `image` or `source` |
| `lineaje_cli_token` | **yes** | — | Lineaje token — always use a secret |
| `org_name` | no | _derived from token_ | Lineaje organization name — auto-extracted from JWT if omitted |
| `project_name` | no | repository name | Lineaje project name |
| `version_prefix` | no | _(none)_ | Short label prepended to the auto-generated version (e.g. `nginx` → `nginx-image-42-1`). Useful when scanning multiple images in one job. |
| `output_dir` | no | `/tmp/lineaje-scan-output` | Directory where veecli writes output |
| `post_scan` | no | `scan_only` | `scan_only` or `fix_plan` (see [post_scan modes](#post_scan-modes)) |

### Image scan inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `image` | **yes** | — | Container image reference, e.g. `docker.io/library/python:3.8-slim` |
| `metafiles` | conditional | — | Path to the Dockerfile — required when `post_scan: fix_plan` (used to generate the patched Dockerfile). Optional for `scan_only`. |
| `image_source_type` | no | `daemon` | `daemon` — image already in local Docker (e.g. just built with `docker build`) · `registry` — pull from registry first |

### Source scan inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `language` | **yes** | — | Runtime to install: `java` · `python` · `node` · `dotnet` |
| `language_version` | **yes** | — | Version to install (see [Supported language versions](#supported-language-versions)) |
| `source_dir` | no | `.` | Path to source directory, relative to repo root |
| `matching_ref` | no | current branch | Branch, tag, or commit being scanned |

---

## Outputs

| Output | Type | Description |
|---|---|---|
| `fix_artifact_uploaded` | `'true'` \| `'false'` | Whether a fix plan artifact was produced and uploaded to the workflow run |
| `patched_dockerfile` | `string` | Absolute path to the patched Dockerfile on the runner (image scan + `fix_plan` only). Empty string otherwise. Use directly with `docker build -f`. |

Artifact contents by scan type:

| Scan type | Artifact name | Files |
|---|---|---|
| `image` | `patched-dockerfile` | Patched `Dockerfile` |
| `source` | `lineaje-fix-plan` | Patched dependency manifest — `pom.xml`, `build.gradle`, `build.gradle.kts`, `requirements.txt`, `Pipfile`, `pyproject.toml`, `package.json`, `package-lock.json` (whichever applies to the project) |

---

## `post_scan` modes

| Value | What happens |
|---|---|
| `scan_only` | Scan only — vulnerability summary printed, no fix plan |
| `fix_plan` | Scan → generate fix plan → download patched artifact → upload as GitHub artifact |

For image scans the uploaded artifact is the patched `Dockerfile`. For source scans it is the patched dependency manifest (`pom.xml`, `build.gradle`, `requirements.txt`, `package.json`, etc.).

---

## Secrets

Add `LINEAJE_CLI_TOKEN` as a repository secret:
**Settings → Secrets and variables → Actions → New repository secret**

Then pass it in your workflow:
```yaml
lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
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
      metafiles: Dockerfile
      lineaje_cli_token: ${{ secrets.LINEAJE_CLI_TOKEN }}
```

---

## Supported language versions

### Java

Pass the **major version** via `language_version`. Maven and all Gradle versions listed below are always installed alongside the JDK.

| `language_version` | JDK installed |
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

**Maven bundled:** 3.9.15
**Gradle bundled:** 4.9, 5.5.1, 5.6.4, 6.3, 6.9.1, 7.4.2, 7.5.1, 7.6.1, 8.0.2, 8.1.1, 8.2, 8.4, 8.6, 8.9

### Python

Pass the **minor version** via `language_version`. Python is built from source on the runner.

Supported: `3.6` · `3.7` · `3.8` · `3.9` · `3.10` · `3.11`

### Node.js

Pass the **major version** via `language_version` (e.g. `18`). Full version strings also accepted.

Supported: `16` (16.20.2) · `18` (18.19.0) · `21` (21.4.0)

### .NET

Pass the **minor version** via `language_version` (e.g. `8.0`). All supported versions are installed together; `language_version` tells the scanner which SDK to use for your project.

Supported: `8.0` · `9.0` · `10.0`

---

## Caching

Runtime downloads (JDK, Maven, Gradle, Python, Node.js, .NET) are cached per `language` + `language_version` via `actions/cache`. On a cache hit the download is skipped entirely, cutting setup time to seconds.

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
