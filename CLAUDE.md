# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A GitHub Actions **composite action** (`action.yml`) that scans container images and source code for vulnerabilities using Lineaje. It downloads the `veecli` binary at runtime, runs it, then polls Lineaje's cloud APIs to retrieve results and optionally generate a fix plan with patched manifests.

## Running and testing

There is no local test suite. The only way to exercise the full action is via GitHub Actions:

- **Manual trigger**: Go to **Actions → Lineaje Scan → Run workflow** in GitHub, which dispatches `.github/workflows/lineaje-scan-gh.yml`. This runs `uses: ./` against the current branch.
- **Lint the Python script locally**:
  ```bash
  python3 -m py_compile lineaje_scan_gh.py
  ```
- **Run the Python script directly** (requires a real `veecli` binary and valid token):
  ```bash
  python3 -m venv .venv && source .venv/bin/activate && pip install requests
  python3 lineaje_scan_gh.py \
    --image docker.io/library/python:3.8-slim \
    --name MyProject --version 1.0 \
    --refresh-token <token> \
    --config-orig /opt/veecli/config-orig.json \
    --veecli /opt/veecli/veecli
  ```

The only runtime dependency for `lineaje_scan_gh.py` is the `requests` package; everything else is stdlib.

## Architecture

### Two-file design

The entire action is two files:

- **`action.yml`** — composite action definition. Handles: input validation, downloading `veecli` tarball, caching runtimes (`/opt/veecli/third_party/linux`), installing .NET, resolving env vars, then invoking `lineaje_scan_gh.py`. Also detects and uploads fix-plan artifacts after the script exits.
- **`lineaje_scan_gh.py`** — Python orchestrator (~1270 lines). Does everything else.

### Scan flow (both modes)

```
0. Install language runtime (Java/Python/Node — source scans only)
1. Exchange refresh token → access token (Lineaje identity service)
2. Build config.json (from veecli's config-orig.json template + access token)
3. Run veecli collect (image or source mode)
4. Parse SBOM job ID from veecli stdout (regex on "SBOM ID - <id>")
5. Poll SCIM API until terminal state ("ready for review" or "failed")
6. Fetch vulnerability summary (GraphQL/LQL data service)
7. Request fix plan from GPT service → poll → download patched artifacts
```

### Scan mode selection

Mode is determined by which CLI flag is provided to `lineaje_scan_gh.py`:
- `--image` → image scan (`veecli collect --image-source <type>:<image>`)
- `--src-folder` → source scan (`veecli collect --inputfile input.json`)

### Key env vars (set by action.yml, consumed by the script)

`VEECLI_PATH`, `CONFIG_ORIG_PATH`, `SOURCE_FOLDER`, `PROJECT_NAME`, `PROJECT_VERSION`, `MATCHING_REF`, `OUTPUT_DIR`

### Multi-scan jobs (scanning original + patched image)

When the action runs more than once in a single job (e.g., scan → patch → rescan pattern), `action.yml` detects `/opt/veecli/veecli` already exists and sets `VEECLI_ALREADY_SETUP=true`, skipping re-download, re-setup, and pip install. The second invocation reuses the existing `config.json` (token already exchanged). The auto-generated `PROJECT_VERSION` appends `-patched` in this case.

### Runtime installation

For source scans, `lineaje_scan_gh.py` installs the requested language runtime into `/opt/veecli/third_party/linux/` before running veecli:

- **Java**: Downloads a specific OpenJDK version + all Maven and all Gradle versions; patches `runtimes-config.json` to fix path mismatches between veecli's bundled paths and the versions we actually install.
- **Python**: Builds from source using `apt` deps + `./configure && make install`; installs `pipdeptree`.
- **Node**: Downloads pre-built tarballs from nodejs.org; note arch key is `arm64` (not `aarch64`).
- **.NET**: Installed in `action.yml` step 4b (not in Python), sets `DOTNET_ROOT` env var.

Runtimes are cached via `actions/cache@v4` keyed on `veecli-runtimes-<language>-<version>`.

### Service endpoints (all read from `config-orig.json`)

| Field in config | Purpose |
|---|---|
| `LineajeAuthService` | Token exchange (refresh → access token) |
| `SCIMHost` | Scan job polling (`/scim/api/v1/sbom_jobs/<id>`) |
| `GraphQLServiceHost` | Vulnerability summary (LQL query) |
| `GPTServiceHost` | Fix plan generation (`/api/v1/explain`) |

### Fix plan polling quirk

The GPT service has two behaviors (documented in `poll_fix_plan`): it either blocks until ready (returns `guid=null, overall_status=available`) or returns immediately with a new `guid`. When `guid` expires (returns `null` but status ≠ `available`), the code re-issues a fresh request without a guid to get a new one.

### Python source scan requirements

veecli requires either a `pyproject.toml` or `setup.py` in the scanned directory to properly resolve a Python project. Without one of these files, veecli falls back to Python 3.9 and may mis-scan or crash. `pyproject.toml` is the recommended approach.

`pipdeptree` must also be present in the action venv (`.venv/bin/pipdeptree`) as a local-env fallback for veecli. `setup_python_runtime` installs it both into each Python version's own environment and into the action venv. Removing the venv install causes veecli's `PythonSrcObject` to have a nil runtime context and crash at `python_srcobject.go:280`.

### Artifact detection (action.yml, not Python)

After `lineaje_scan_gh.py` exits, `action.yml` step 11 scans `$OUTPUT_DIR` for known filenames to set `fix_artifact_uploaded=true/false` and `patched_dockerfile=<path>`. The Python script itself does not set these outputs.

## Supported versions

- **Java**: 8–25 (only specific patch releases are bundled in `OPENJDK_RELEASES`)
- **Python**: 3.6–3.14 (built from source; Python 3.6 requires `pip-python36.patch` from veecli)
- **Node**: 16.20.2, 18.19.0, 20.18.0, 21.4.0, 22.11.0, 24.15.0, 26.2.0
- **.NET**: 6.0, 7.0, 8.0, 9.0, 10.0

## Platforms

Linux only (`ubuntu-latest`). Supports x86_64 and aarch64. Node uses `arm64` as the arch string (not `aarch64`); Java uses `aarch64` for versions 15+.
