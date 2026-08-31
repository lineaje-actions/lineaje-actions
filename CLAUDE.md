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

### File layout

Two files carry the logic:

- **`action.yml`** — composite action definition. Handles: input validation, downloading `veecli` tarball, caching runtimes (`/opt/veecli/third_party/linux`), installing .NET, resolving env vars, then invoking `lineaje_scan_gh.py`. Captures stdout+stderr via `tee` to parse ECH counts after the script exits. Also detects and uploads fix-plan artifacts.
- **`lineaje_scan_gh.py`** — Python orchestrator. Does everything else.

Plus assets it copies or renders at runtime, used only by `post_scan=fix_plan_gos_compat`:

- **`lineaje-verify.sh`** — the verify hook, copied verbatim into the veecli dir. It receives `--language` from the rendered fix config and runs only that ecosystem's verifier: Python installs recursive `requirements.txt` files into a shared venv; Node runs `npm install` for recursive `package.json` files with a local cache and the generated npmrc. It exits 1 on installation failure and skips unsupported languages.
- **`templates/{fix.yaml,npmrc,pip.conf}`** (the fix template renders to `fix.yml`/`fix.yaml`) — rendered by `_render_template()`, which substitutes `__KEY__` placeholders and **raises on any leftover placeholder**, so a renamed key fails loudly instead of producing config veecli silently misreads. Watch out for prose in template comments that looks like a placeholder — it trips the guard.

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
- **.NET**: Installed in `action.yml` step 4b (not in Python), sets `DOTNET_ROOT` env var. Also installs the `CycloneDX` dotnet tool (SBOM generator) pinned to **`5.5.0`**, confirmed 2026-08-07 by running `dotnet-CycloneDX --help` for that exact version in a container: it's the last release before `cyclonedx-dotnet` 6.0.0 (2026-02-08) removed the deprecated short flags outright. veecli's collector unconditionally invokes `dotnet-CycloneDX` with `-d -t -st library -j -r -dgl -o <dir> -f <file> -tfm <tfm> -sv <ref> -rs <path>` (partly from its bundled `tools-config.json`'s static `command` string for the `CycloneDXProvider`/`dotnet-cyclonedx` entry — which still declares `"version": "2.7.0"` and is not patched by this repo — partly hardcoded in veecli's own compiled binary, which is *not* patchable from here at all). `5.5.0` is the only version where every one of those flags is simultaneously valid: `-d`/`-j`/`-r`/`-dgl`/`-f` all still work as deprecated aliases (`-ed`/`--output-format json`/`-rs`/default-now/`-fn` are their respective replacements), and `-rs` already exists too. `2.7.0` predates `-rs` entirely ("Unrecognized option '-rs'"); `6.2.0`+ has removed `-d`/`-j`/`-r`/`-dgl`/`-f` entirely ("Unrecognized command or argument"). If a dotnet scan ever regresses again (SBOM reaches "Ready for review" but resolves 0 real components; check `dotnet-CycloneDX` stderr in the veecli log), re-verify this pin is still the sweet spot — `dotnet tool install --version <X> CycloneDX` then `dotnet-CycloneDX --help` in a container is the fast way to check a candidate version's flag support directly rather than guessing from changelogs.
- **Rust**: Installed in `action.yml` step 4c (not in Python), mirroring the `.NET` pattern — no `runtimes-config.json`/`tools-config.json` patching, since veecli discovers Cargo projects and tools via `PATH`/env vars rather than a pinned config entry. Installs `rustup` with no default toolchain (`--default-toolchain none`), then explicitly installs and defaults to the requested `language_version` via `rustup toolchain install`/`rustup default` (unlike the upstream veecli team's own installer script, which just takes whatever `rustup` resolves as current stable — pinning was a deliberate deviation so `language_version` behaves consistently with the other languages). Also installs `cargo-lock` (the CycloneDX-adjacent tool veecli uses to read `Cargo.lock`) and `coldsnap` (AWS EBS/AMI snapshot tool — unrelated to source scanning, but included because it's part of veecli's own reference install script for this environment). Sets `RUSTUP_HOME`/`CARGO_HOME` and prepends `third_party/linux/cargo/bin` to `PATH`.

Runtimes are cached via `actions/cache@v4` keyed on `veecli-runtimes-<language>-<version>` (Go cache key also includes `-cdxgomod-1.10.0-3-lineaje` to bust stale cache on version bumps).

### Service endpoints (all read from `config-orig.json`)

| Field in config | Purpose |
|---|---|
| `LineajeAuthService` | Token exchange (refresh → access token) |
| `SCIMHost` | Scan job polling (`/scim/api/v1/sbom_jobs/<id>`) |
| `GraphQLServiceHost` | Vulnerability summary (LQL query) |
| `GPTServiceHost` | Fix plan generation (`/api/v1/explain`) |

### `post_scan=fix_plan_gos_compat` (source scans only)

A third post-scan mode layered on top of `fix_plan`. After the normal fix plan comes back, two extra steps run in `_run_fix_plan` (`gos=True`) instead of `download_artifacts`:

0. `write_fix_config` writes the fix config to **four paths** — `fix.yml` and `fix.yaml`, in both `<veecli_dir>` and `~/veecli/` — plus three files the verify hook needs: `lineaje-verify.sh`, `lineaje-verify.npmrc`, and `lineaje-verify-pip.conf`. Only the fix.yaml keys that apply when applying **without a PR** are emitted — `pull_request`, `reviewers` and `credentials` are omitted, the last deliberately, since it would put SCM tokens on disk for no benefit.

   `verify-local-files-actions` is always configured. veecli's Verify Local Files Agent runs it against a task's local task dir before copying patched files into the local workflow dir, and **a non-zero exit skips the copy and fails the agent** — hence two deliberate choices. First, the hook points at a script this action writes rather than a conventional path in the user's repo; a missing script would abort every patch. Second, the script is **blocking**: a manifest whose pins will not install is rejected rather than copied, since an uninstallable patch is not a usable one.

  The script handles Python and Node explicitly based on the action's `language` input. Python finds all `requirements.txt` files recursively under `--task-dir` and installs them into a single shared venv. Node finds `package.json` files outside `node_modules`, runs `npm install` in each package directory, and shares a temporary cache across those installs. Other languages skip dependency verification.

   The npmrc is why the registry configuration matters so much now that the hook blocks: GOS patches resolve to Lineaje-rebuilt versions like `helmet@2.3.0-lineaje-01` that exist **only** in the fortknox premium registry, so a plain `npm install` 404s and rejects exactly the patches this mode exists to produce. The npmrc is written even though veecli should already export `GOS_PREMIUM_*` into the hook's environment — npm reads a config file either way. Both the global and registry-scoped `_auth` forms are emitted; the exact form Artifactory wants is unverified. Python has no GOS index at all, so its side uses `pip_extra_index_url` (via `PIP_CONFIG_FILE`). Both credential files are `chmod 600`, and neither the token nor the npmrc contents are ever logged.

   The four-path write exists because veecli reported `No verify local files script was configured in fix.yaml` while the known-good config on disk elsewhere is named **`fix.yml`**. Which name and directory it actually reads is still unconfirmed; the run log echoes the rendered config and lists every path written, so the next failure narrows it. Note the warning itself proves the Verify Local Files Agent exists in the binary — it only fires from that code path.

  The `connect_to_fortknox` action input (default `true`) lets a customer opt out of Fortknox entirely: `write_fix_config` skips writing the npmrc and passes `--connect-to-fortknox false` into `fix.yaml`'s verify-hook args, and `lineaje-verify.sh`'s node case then points `npm install --registry` at `registry.npmjs.org` instead of `GOS_PREMIUM_NPM_REGISTRY`. Since the hook is blocking, any patch that needed a Lineaje-rebuilt (`-lineaje-N`) version simply fails to install and is rejected — never copied into the uploaded output — which is what "never suggest a Lineaje package" actually reduces to. This is Node-only: Python's side (`pip_extra_index_url`/`pip.conf`) never had a Fortknox/GOS index to disconnect from, so the flag has no effect there. Skipping just the npmrc write would **not** have been sufficient on its own — npm's `--registry` value comes from the `GOS_PREMIUM_NPM_REGISTRY` env var directly (`_gos_premium_env`, always set), not from the npmrc file, so the hook needed its own flag to change *which* registry it targets, not just drop the credentials for the existing one.

  Note `GOS_PREMIUM_NPM_REGISTRY` is currently hardcoded to `fortknox.commercialdev.dev.veedna.com` and does **not** honour the `*_url` endpoint override inputs.
1. `apply_fix_left_plan` POSTs to `/api/v1/explain` with `query="Apply fix left plan without pr"` and `metadata.components` set to the fix plan's `plan_details` **verbatim**. The backend checks each `suggested_purl` against the GOS artifactory (Lineaje-rebuilt versions like `pkg:npm/helmet@2.3.0-lineaje-01`) and queues patch tasks. This action never queries the artifactory directly and does no client-side filtering of `plan_details` — deliberately, so the filter can't drift from the backend's.

   **This call is asynchronous and must be polled.** The first POST (no guid) returns a guid, `message="Request is being processed"`, and an empty `task_ids`. Subsequent POSTs repeat the *entire* body — same query, same `metadata.components` — plus that guid, until `task_ids` is populated and the message becomes `"Created tasks for AI Agents. Request is being processed"`. Returning early leaves step 2 with no tasks to wait on, so it would exit having patched nothing. The readiness check keys on `task_ids` being non-empty first and the message string second, since the wording is the likelier thing to drift — at least three pending wordings exist (`Request is being processed`, `Request is still processing. Please try again later.`, and the ready message, which contains the first). Completion-with-no-tasks is matched against an explicit allowlist (`APPLY_FIX_DONE_MESSAGES`); do **not** infer it from the absence of a known pending phrase, which is how an unseen wording once made the poll give up on its first tick and report "nothing matched" for a plan that was still being built. Unknown wording must keep polling. Guid expiry (`guid: null` mid-poll) is handled the same way `poll_fix_plan` does it — the next poll omits the guid to get a fresh handle.
2. `run_veecli_fix` runs `veecli fix --poll-tasks --local-repo-dir <src> --output-fix-dir <out>/fix --sbom-id <id>`, which blocks on those tasks and writes patched manifests preserving the repo layout.

Both steps run inside `_run_fix_plan`'s existing try/except, so failures warn rather than fail the scan — hence `_run_veecli` gained a `fatal` parameter (`RuntimeError` instead of `sys.exit`, since `SystemExit` escapes `except Exception`).

Gotchas when touching this: `action.yml` had two exact `= "fix_plan"` string comparisons ([step 1](action.yml) metafiles validation, step 1b Go fallback) that silently did the wrong thing for a new mode value — both are now `!= "scan_only"`. Step 11 exports a `post_scan_effective` step output (undeclared in `outputs:`, internal use only) so the two mutually-exclusive source upload steps can tell `fix_plan` from `fix_plan_gos_compat`; `POST_SCAN_EFFECTIVE` alone isn't enough because the Go fallback rewrites it.

### Fix plan polling quirk

The GPT service has two behaviors (documented in `poll_fix_plan`): it either blocks until ready (returns `guid=null, overall_status=available`) or returns immediately with a new `guid`. When `guid` expires (returns `null` but status ≠ `available`), the code re-issues a fresh request without a guid to get a new one.

`_run_fix_plan` writes the complete response to `<output_dir>/raw-fix-plan.json` before handling no-fix responses or downloading/applying patched artifacts, for both `fix_plan` and `fix_plan_gos_compat`. `action.yml` uploads it separately as `lineaje-raw-fix-plan`; it does not affect the existing `fix_artifact_uploaded` output.

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
