#!/usr/bin/env bash
# Copyright 2026 Lineaje, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# veecli's Verify Local Files Agent runs this against a task's local task
# directory before copying the patched files into the local workflow directory.
# write_fix_config() in lineaje_scan_gh.py copies it into the veecli directory
# and points fix.yaml's verify-local-files-actions at that copy.
#
# Installs dependencies for the selected language under the task directory:
# requirements.txt through a Python venv, or package.json through npm. A
# non-zero exit makes veecli skip the copy and fail the agent.
#
# Usage:
#   ./lineaje-verify.sh --task-dir DIR --language python|node [--node-bin-dir DIR]
#
# Falls back to $LOCAL_TASK_DIR then $PWD when --task-dir is absent, so it works
# both under veecli's Verify Local Files Agent and when run by hand. Unrecognised
# arguments are ignored rather than treated as errors, so extra flags the agent
# passes do not break it.
#
# Exit codes:
#   0 - success (including the case where no manifest files were found)
#   1 - a manifest file was found but its install command failed

set -u
set -o pipefail

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log() {
    printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

log_info()  { log "INFO  - $*"; }
log_error() { log "ERROR - $*"; }

print_redacted_log() {
    local path="$1"
    [[ -f "$path" ]] || return
    sed -E 's#(https?://)[^[:space:]]*@#\1***:***@#g' "$path"
}

verify_lockfile_versions() {
    local package_dir="$1"
    [[ -f "${package_dir}/package-lock.json" ]] || return 0

    (cd "$package_dir" && node <<'NODE'
const fs = require("fs");
const path = require("path");

const lock = JSON.parse(fs.readFileSync("package-lock.json", "utf8"));
const mismatches = [];

for (const [relativePath, locked] of Object.entries(lock.packages || {})) {
    if (!relativePath.includes("node_modules/") || !locked.version || locked.link) {
        continue;
    }

    const manifestPath = path.join(relativePath, "package.json");
    if (!fs.existsSync(manifestPath)) {
        continue;
    }

    const installed = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    if (installed.version !== locked.version) {
        mismatches.push(`${relativePath}: lock=${locked.version}, installed=${installed.version || "<missing>"}`);
    }
}

if (mismatches.length > 0) {
    console.error("Installed package versions do not match package-lock.json:");
    for (const mismatch of mismatches) console.error(`  ${mismatch}`);
    process.exit(1);
}
NODE
    )
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PIP_CONFIG="${SCRIPT_DIR}/lineaje-verify-pip.conf"
NPM_CONFIG="${SCRIPT_DIR}/lineaje-verify.npmrc"

REPO_ROOT=""
LANGUAGE=""
NODE_BIN_DIR=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --task-dir) REPO_ROOT="${2:-}"; shift 2 ;;
        --language) LANGUAGE="${2:-}"; shift 2 ;;
        --node-bin-dir) NODE_BIN_DIR="${2:-}"; shift 2 ;;
        *)          shift ;;
    esac
done
[[ -n "$REPO_ROOT" ]] || REPO_ROOT="${LOCAL_TASK_DIR:-$PWD}"

WORKDIR="$(mktemp -d "/tmp/lineaje-verify.XXXXXX")"

log_info "Scanning directory: ${REPO_ROOT}"
log_info "Created temporary working directory: ${WORKDIR}"

# Track whether any manifest was found, and whether any install failed.
FOUND_ANY_MANIFEST=0
ANY_INSTALL_FAILED=0
NODE_PACKAGE_DIRS=()
GENERATED_LOCKFILES=()

cleanup_node_install_artifacts() {
    local package_dir lockfile
    for package_dir in "${NODE_PACKAGE_DIRS[@]}"; do
        rm -rf "${package_dir}/node_modules"
    done
    for lockfile in "${GENERATED_LOCKFILES[@]}"; do
        rm -f "$lockfile"
    done
}

trap cleanup_node_install_artifacts EXIT

case "$LANGUAGE" in
    python)
        if [[ -f "$PIP_CONFIG" ]]; then
            export PIP_CONFIG_FILE="$PIP_CONFIG"
            unset PIP_EXTRA_INDEX_URL
            log_info "Using pip configuration: ${PIP_CONFIG}"
        fi

        log_info "Searching recursively for requirements.txt under ${REPO_ROOT}"
        REQUIREMENTS_FILES=()
        while IFS= read -r file; do
            REQUIREMENTS_FILES+=("$file")
        done < <(find "${REPO_ROOT}" -type f -name "requirements.txt" 2>/dev/null)

        if [[ "${#REQUIREMENTS_FILES[@]}" -eq 0 ]]; then
            log_info "No requirements.txt found."
        else
            FOUND_ANY_MANIFEST=1
            log_info "Found ${#REQUIREMENTS_FILES[@]} requirements.txt file(s):"
            for f in "${REQUIREMENTS_FILES[@]}"; do
                log_info "  - ${f}"
            done

            VENV_DIR="${WORKDIR}/venv"
            log_info "Creating Python virtual environment at ${VENV_DIR}"
            if ! python3 -m venv "${VENV_DIR}" >>"${WORKDIR}/venv_create.log" 2>&1; then
                log_error "Failed to create virtual environment. Redacted output follows:"
                print_redacted_log "${WORKDIR}/venv_create.log"
                ANY_INSTALL_FAILED=1
            else
                # shellcheck disable=SC1091
                source "${VENV_DIR}/bin/activate"
                log_info "Virtual environment activated: $(which python3)"

                for req in "${REQUIREMENTS_FILES[@]}"; do
                    pip_log="${WORKDIR}/pip_install.log"
                    : > "$pip_log"
                    log_info "Running: pip install -r ${req}"
                    if pip install -r "${req}" >>"$pip_log" 2>&1; then
                        log_info "pip install succeeded for ${req}"
                    else
                        log_error "pip install FAILED for ${req}. Redacted pip output follows:"
                        print_redacted_log "$pip_log"
                        ANY_INSTALL_FAILED=1
                    fi
                done

                deactivate
                log_info "Deactivated virtual environment."
            fi
        fi
        ;;
    node)
        if [[ -n "$NODE_BIN_DIR" ]]; then
            export PATH="${NODE_BIN_DIR}:${PATH}"
        fi
        if [[ -f "$NPM_CONFIG" ]]; then
            export NPM_CONFIG_USERCONFIG="$NPM_CONFIG"
            log_info "Using npm configuration: ${NPM_CONFIG}"
        fi
        if ! command -v npm >/dev/null 2>&1; then
            log_error "npm not found (node bin directory: ${NODE_BIN_DIR:-not provided})."
            exit 1
        fi
        if [[ -z "${GOS_PREMIUM_NPM_REGISTRY:-}" ]]; then
            log_error "GOS_PREMIUM_NPM_REGISTRY is not set."
            exit 1
        fi
        NPM_REGISTRY="${GOS_PREMIUM_NPM_REGISTRY%/}/"
        log_info "Using npm registry: ${NPM_REGISTRY}"

        NPM_CACHE_DIR="${WORKDIR}/npm-cache"
        mkdir -p "$NPM_CACHE_DIR"
        log_info "Searching recursively for package.json under ${REPO_ROOT}"
        PACKAGE_JSON_FILES=()
        while IFS= read -r file; do
            PACKAGE_JSON_FILES+=("$file")
        done < <(find "${REPO_ROOT}" -type f -name "package.json" -not -path "*/node_modules/*" 2>/dev/null)

        if [[ "${#PACKAGE_JSON_FILES[@]}" -eq 0 ]]; then
            log_info "No package.json found."
        else
            FOUND_ANY_MANIFEST=1
            log_info "Found ${#PACKAGE_JSON_FILES[@]} package.json file(s):"
            for f in "${PACKAGE_JSON_FILES[@]}"; do
                log_info "  - ${f}"
            done

            for pkg in "${PACKAGE_JSON_FILES[@]}"; do
                pkg_dir="$(dirname "${pkg}")"
                NODE_PACKAGE_DIRS+=("$pkg_dir")
                if [[ ! -f "${pkg_dir}/package-lock.json" ]]; then
                    GENERATED_LOCKFILES+=("${pkg_dir}/package-lock.json")
                fi
                npm_log="${WORKDIR}/npm_install.log"
                : > "$npm_log"
                log_info "Running: npm install (cwd=${pkg_dir}, cache=${NPM_CACHE_DIR})"
                if (cd "${pkg_dir}" && npm install --registry "${NPM_REGISTRY}" --cache "${NPM_CACHE_DIR}" >>"$npm_log" 2>&1); then
                    log_info "npm install succeeded in ${pkg_dir}; validating dependency tree"
                    if (cd "${pkg_dir}" && npm ls --all --json >>"$npm_log" 2>&1); then
                        if verify_lockfile_versions "$pkg_dir" >>"$npm_log" 2>&1; then
                            log_info "npm dependency tree and installed versions are valid in ${pkg_dir}"
                        else
                            log_error "Installed npm package versions do not match the lockfile in ${pkg_dir}. Redacted output follows:"
                            print_redacted_log "$npm_log"
                            ANY_INSTALL_FAILED=1
                        fi
                    else
                        log_error "npm dependency validation FAILED in ${pkg_dir}. Redacted npm output follows:"
                        print_redacted_log "$npm_log"
                        ANY_INSTALL_FAILED=1
                    fi
                else
                    log_error "npm install FAILED in ${pkg_dir}. Redacted npm output follows:"
                    print_redacted_log "$npm_log"
                    ANY_INSTALL_FAILED=1
                fi
            done
        fi
        ;;
    *)
        log_info "No dependency verifier configured for language: ${LANGUAGE:-<empty>}. Exiting 0."
        exit 0
        ;;
esac

# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------
if [[ "${FOUND_ANY_MANIFEST}" -eq 0 ]]; then
    log_info "No ${LANGUAGE} manifest files found anywhere in the repo. Exiting 0."
    exit 0
fi

if [[ "${ANY_INSTALL_FAILED}" -eq 1 ]]; then
    log_error "One or more dependency installations failed. Exiting 1."
    exit 1
fi

log_info "All discovered manifest files were installed successfully. Exiting 0."
exit 0
