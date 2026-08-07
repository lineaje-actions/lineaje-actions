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

- **`action.yml`** — composite action definition. Handles: input validation, downloading `veecli` tarball, caching runtimes (`/opt/veecli/third_party/linux`), installing .NET, resolving env vars, then invoking `lineaje_scan_gh.py`. Captures stdout+stderr via `tee` to parse ECH counts after the script exits. Also detects and uploads fix-plan artifacts.
- **`lineaje_scan_gh.py`** — Python orchestrator (~1400 lines). Does everything else.

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

- **Java**: Downloads a specific OpenJDK version + all Maven (3.8.9 — pinned to match veecli's bundled `tools-config.json`, which hardcodes its lone `MvnProvider` entry to `maven-3.8.9`; a newer Maven produced different `exec:exec` plugin-resolution output that broke veecli's properties-task parser and silently produced zero components) and all Gradle versions; downloaded from `archive.apache.org` since `dlcdn.apache.org` only mirrors the latest release train and 404s on older versions. `patch_runtimes_config` fixes JDK path mismatches in `runtimes-config.json`; `patch_tools_config_maven` defensively keeps `tools-config.json`'s Maven entry in sync with `MAVEN_VERSION`/`MAVEN_DIR` in case that pin ever changes again. Java 15+ supports aarch64; Java 25 is x64-only.
- **Python**: Builds from source using `apt` deps (including `liblzma-dev` and `zlib1g-dev` required for Python 3.12+) + `./configure && make install`. After building, three things happen: (1) pipdeptree is installed into each Python version's own `bin/` so veecli can use it as a tool provider; (2) pipdeptree is also installed into the action venv as a fallback to prevent veecli nil-pointer crashes; (3) each installed Python's `bin/` is prepended to `os.environ["PATH"]` so veecli can discover the binary when resolving `requires-python` constraints. `patch_runtimes_config_python` adds the version to `runtimes-config.json` (pointing to the full binary path) so veecli correctly initialises the Python version.
- **Node**: Downloads pre-built tarballs from nodejs.org; note arch key is `arm64` (not `aarch64`).
- **Go**: Downloads the official Go tarball from `go.dev/dl/` into `third_party/linux/go-{minor}/`. Also downloads `cyclonedx-gomod` v1.10.0-3-lineaje from the `lineaje-labs/cyclonedx-gomod` fork (NOT the upstream CycloneDX repo) and symlinks it into `go-{minor}/bin/`. Runs `go env -w` to persist `GOPROXY` and `GONOSUMDB` settings. Calls `patch_runtimes_config_go` to add the version to `runtimes-config.json` for versions not present in veecli's bundled config (1.19, 1.20, 1.22, 1.24, 1.26). Checks for a `vendor/` directory before running `go mod tidy`.
- **.NET**: Installed in `action.yml` step 4b (not in Python), sets `DOTNET_ROOT` env var. Also installs the `CycloneDX` dotnet tool (SBOM generator) pinned to a specific version — currently `6.2.0`. This pin is fragile in the same way as the Maven pin: since `action.yml` always downloads `veecli_latest.tar.gz`, veecli's own expected CLI invocation can drift out from under whatever version we pin here. It was bumped from `2.7.0` → `6.2.0` on 2026-08-07 after veecli started invoking the tool with `-rs`/`--scan-project-references` (added in `cyclonedx-dotnet` v6.0.0, replacing the removed `-r`/`--recursive` flag) — 2.7.0 predated that flag entirely and failed with "Unrecognized option '-rs'", silently producing zero resolved components. If a future dotnet scan fails the same way (SBOM created but 0 components resolved, `dotnet-CycloneDX` stderr complaining about an unrecognized option), check `https://github.com/CycloneDX/cyclonedx-dotnet/releases` and `CHANGELOG.md` for the CLI contract veecli's installed version now expects, since we don't patch `tools-config.json`'s static `CycloneDXProvider` command args for dotnet the way `patch_tools_config_maven` does for Maven — only the tool *version* is controlled here.
- **Rust**: Installed in `action.yml` step 4c (not in Python), mirroring the `.NET` pattern — no `runtimes-config.json`/`tools-config.json` patching, since veecli discovers Cargo projects and tools via `PATH`/env vars rather than a pinned config entry. Installs `rustup` with no default toolchain (`--default-toolchain none`), then explicitly installs and defaults to the requested `language_version` via `rustup toolchain install`/`rustup default` (unlike the upstream veecli team's own installer script, which just takes whatever `rustup` resolves as current stable — pinning was a deliberate deviation so `language_version` behaves consistently with the other languages). Also installs `cargo-lock` (the CycloneDX-adjacent tool veecli uses to read `Cargo.lock`) and `coldsnap` (AWS EBS/AMI snapshot tool — unrelated to source scanning, but included because it's part of veecli's own reference install script for this environment). Sets `RUSTUP_HOME`/`CARGO_HOME` and prepends `third_party/linux/cargo/bin` to `PATH`.

Runtimes are cached via `actions/cache@v4` keyed on `veecli-runtimes-<language>-<version>` (Go cache key also includes `-cdxgomod-1.10.0-3-lineaje` to bust stale cache on version bumps).

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

### ECH output (action.yml, not Python)

After `lineaje_scan_gh.py` exits, `action.yml` step 11 uses `awk` to parse the scan log (captured via `tee /tmp/lineaje-scan-XXXXXX.log`) for `Exploited:`, `Critical:`, and `High:` lines and sums them into `ech_count`. This is emitted as a GitHub Actions output. `PIPESTATUS[0]` is used to preserve the Python exit code through the `tee` pipe.

### Artifact detection (action.yml, not Python)

After `lineaje_scan_gh.py` exits, `action.yml` step 11 scans `$OUTPUT_DIR` for known filenames to set `fix_artifact_uploaded=true/false` and `patched_dockerfile=<path>`. The Python script itself does not set these outputs.

## Supported versions

- **Java**: 8–25 (only specific patch releases are bundled in `OPENJDK_RELEASES`)
- **Python**: 3.6–3.14 (built from source; Python 3.6 requires `pip-python36.patch` from veecli)
- **Node**: 16.20.2, 18.19.0, 20.18.0, 21.4.0, 22.11.0, 24.15.0, 26.2.0
- **.NET**: 6.0, 7.0, 8.0, 9.0, 10.0
- **Go**: 1.18–1.26 (user passes minor version e.g. `1.21`; resolves to latest patch via `GO_VERSIONS` dict). Also installs `cyclonedx-gomod` v1.10.0-3-lineaje (Lineaje Labs fork at `lineaje-labs/cyclonedx-gomod`) as the SBOM tool. Sets `GOROOT` and prepends `go-{minor}/bin` to `PATH` before invoking veecli.
- **Rust**: any `rustup`-resolvable toolchain version (e.g. `1.75.0`) — no fixed version list, `rustup toolchain install` resolves it directly. Also installs `cargo-lock` and `coldsnap` as tools.

## Platforms

Linux only (`ubuntu-latest`). Supports x86_64 and aarch64. Node uses `arm64` as the arch string (not `aarch64`); Java uses `aarch64` for versions 15–24 (Java 25 is x64-only on jdk.java.net at time of writing).
