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
# Verifies the patched manifest for the selected language under the task
# directory: requirements.txt through a Python venv, package.json through npm,
# pom.xml through Maven resolve + test-compile and build.gradle[.kts] through
# Gradle compileJava + compileTestJava (no test execution — see the java case
# below), go.mod through `go build ./...`, or .NET project files through
# `dotnet restore` (see the dotnet case). A non-zero exit makes veecli skip the
# copy and fail the agent.
#
# Usage:
#   ./lineaje-verify.sh --task-dir DIR --language python|node|java|go|golang|dotnet \
#       [--node-bin-dir DIR] [--mvn-bin-dir DIR] [--gradle-install-dir DIR] \
#       [--dotnet-bin-dir DIR] [--go-bin-dir DIR] \
#       [--repo-root DIR] [--connect-to-fortknox true|false]
#
# --repo-root (java, go and dotnet) is the original full repository checkout, as
# opposed to --task-dir, which veecli populates with only the specific file(s)
# a patch task touches (e.g. just core/pom.xml out of a core+app reactor, or
# just go.mod out of a module with a local `replace` directive) — not a full
# copy of the project. A Maven multi-module build needs the parent POM and
# sibling modules; a Go module with a relative `replace` needs its target; a
# .NET project needs its ProjectReferences and Directory.*.props — all need
# the whole tree. When --repo-root is given, these cases reconstruct
# it: copy --repo-root, then overlay --task-dir's patched file(s) on top at
# their same relative paths, and build that. Without --repo-root, they fall
# back to treating --task-dir as the whole project, same as the python/node
# cases do — correct only when there's no parent/sibling/replace-path
# dependency.
#
# --connect-to-fortknox false (default true) makes the node case check
# package.json against the public npm registry, the java case check pom.xml
# against Maven Central, and the dotnet case restore from nuget.org only,
# instead of the Fortknox GOS premium registry, so
# Lineaje-rebuilt (-lineaje-N) packages fail to resolve and their patches are
# rejected. No effect on the python case, which never used Fortknox. No effect
# on the go case either — there is no GOS/Fortknox Go module proxy yet, so it
# always uses the public Go proxy regardless of this flag.
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
MAVEN_SETTINGS="${SCRIPT_DIR}/lineaje-verify-settings.xml"
NUGET_CONFIG="${SCRIPT_DIR}/lineaje-verify.nuget.config"
GRADLE_INIT="${SCRIPT_DIR}/lineaje-verify-init.gradle"

REPO_ROOT=""
LANGUAGE=""
NODE_BIN_DIR=""
MVN_BIN_DIR=""
GRADLE_INSTALL_DIR=""
GO_BIN_DIR=""
DOTNET_BIN_DIR=""
ORIG_REPO_ROOT=""
CONNECT_TO_FORTKNOX="true"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --task-dir) REPO_ROOT="${2:-}"; shift 2 ;;
        --language) LANGUAGE="${2:-}"; shift 2 ;;
        --node-bin-dir) NODE_BIN_DIR="${2:-}"; shift 2 ;;
        --mvn-bin-dir) MVN_BIN_DIR="${2:-}"; shift 2 ;;
        --gradle-install-dir) GRADLE_INSTALL_DIR="${2:-}"; shift 2 ;;
        --go-bin-dir) GO_BIN_DIR="${2:-}"; shift 2 ;;
        --dotnet-bin-dir) DOTNET_BIN_DIR="${2:-}"; shift 2 ;;
        --repo-root) ORIG_REPO_ROOT="${2:-}"; shift 2 ;;
        --connect-to-fortknox) CONNECT_TO_FORTKNOX="${2:-true}"; shift 2 ;;
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
JAVA_PROJECT_DIRS=()
DOTNET_PROJECT_DIRS=()
GRADLE_PROJECT_DIRS=()

cleanup_verify_artifacts() {
    # The "${ARR[@]+"${ARR[@]}"}" form (rather than plain "${ARR[@]}") avoids an
    # "unbound variable" error under `set -u` when the array is empty on bash
    # versions older than 4.4 — this trap always runs, including when nothing
    # of that kind was found.
    local package_dir lockfile project_dir
    for package_dir in "${NODE_PACKAGE_DIRS[@]+"${NODE_PACKAGE_DIRS[@]}"}"; do
        rm -rf "${package_dir}/node_modules"
    done
    for lockfile in "${GENERATED_LOCKFILES[@]+"${GENERATED_LOCKFILES[@]}"}"; do
        rm -f "$lockfile"
    done
    for project_dir in "${JAVA_PROJECT_DIRS[@]+"${JAVA_PROJECT_DIRS[@]}"}"; do
        find "$project_dir" -type d -name target -prune -exec rm -rf {} +
    done
    for project_dir in "${DOTNET_PROJECT_DIRS[@]+"${DOTNET_PROJECT_DIRS[@]}"}"; do
        rm -rf "${project_dir}/obj"
    done
    # Gradle output: only a `build` dir sitting next to a Gradle build script is
    # removed, so a source directory that merely happens to be named "build" is not.
    local gdir bdir
    for gdir in "${GRADLE_PROJECT_DIRS[@]+"${GRADLE_PROJECT_DIRS[@]}"}"; do
        while IFS= read -r bdir; do
            if [[ -f "$(dirname "$bdir")/build.gradle" || -f "$(dirname "$bdir")/build.gradle.kts" ]]; then
                rm -rf "$bdir"
            fi
        done < <(find "$gdir" -type d -name build 2>/dev/null)
        find "$gdir" -type d -name .gradle -prune -exec rm -rf {} + 2>/dev/null
    done
}

trap cleanup_verify_artifacts EXIT

# --task-dir only contains the specific file(s) a patch task touches (e.g.
# just core/pom.xml out of a core+app reactor, or just go.mod out of a module
# with a local `replace` directive) — not a full copy of the project. Maven's
# parent POM and Go's relative `replace` targets both need the whole tree to
# resolve (as do a .NET project's ProjectReferences and Directory.*.props). When --repo-root (the real checkout) is available, reconstruct it:
# copy --repo-root, then overlay --task-dir's patched file(s) on top at their
# real relative paths, and build from that instead. Sets BUILD_ROOT. Without
# --repo-root, falls back to treating --task-dir as the whole project —
# correct only when there's no parent/sibling/replace-path dependency.
reconstruct_build_root() {
    if [[ -n "$ORIG_REPO_ROOT" && -d "$ORIG_REPO_ROOT" ]]; then
        BUILD_ROOT="${WORKDIR}/project"
        mkdir -p "$BUILD_ROOT"
        log_info "Reconstructing full project at ${BUILD_ROOT} (base: ${ORIG_REPO_ROOT}, patched overlay: ${REPO_ROOT})"
        cp -a "${ORIG_REPO_ROOT}/." "${BUILD_ROOT}/"
        rm -rf "${BUILD_ROOT}/.git"
        cp -a "${REPO_ROOT}/." "${BUILD_ROOT}/"
    else
        BUILD_ROOT="${REPO_ROOT}"
    fi
}

case "$LANGUAGE" in
    python)
        if [[ -f "$PIP_CONFIG" ]]; then
            export PIP_CONFIG_FILE="$PIP_CONFIG"
            unset PIP_EXTRA_INDEX_URL
            log_info "Using pip configuration: ${PIP_CONFIG}"
        fi

        # Same reasoning as the Maven repo cache below: pip's wheel/http cache
        # is keyed by content, so reuse is safe, and pinning it under
        # SCRIPT_DIR makes it explicit and cacheable across workflow runs
        # (the venv itself is still fresh per invocation).
        PIP_CACHE="${SCRIPT_DIR}/third_party/pip-verify-cache"
        if ! mkdir -p "$PIP_CACHE" 2>/dev/null; then
            PIP_CACHE="${WORKDIR}/pip-cache"
            mkdir -p "$PIP_CACHE"
        fi
        export PIP_CACHE_DIR="$PIP_CACHE"
        log_info "Using pip cache: ${PIP_CACHE}"

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
        if ! command -v npm >/dev/null 2>&1; then
            log_error "npm not found (node bin directory: ${NODE_BIN_DIR:-not provided})."
            exit 1
        fi
        if [[ "$CONNECT_TO_FORTKNOX" = "true" ]]; then
            if [[ -f "$NPM_CONFIG" ]]; then
                export NPM_CONFIG_USERCONFIG="$NPM_CONFIG"
                log_info "Using npm configuration: ${NPM_CONFIG}"
            fi
            if [[ -z "${GOS_PREMIUM_NPM_REGISTRY:-}" ]]; then
                log_error "GOS_PREMIUM_NPM_REGISTRY is not set."
                exit 1
            fi
            NPM_REGISTRY="${GOS_PREMIUM_NPM_REGISTRY%/}/"
        else
            NPM_REGISTRY="https://registry.npmjs.org/"
            log_info "connect_to_fortknox=false — using the public npm registry; Lineaje-rebuilt packages will not resolve and their patches will be rejected"
        fi
        log_info "Using npm registry: ${NPM_REGISTRY}"

        # Same reasoning as the Maven repo cache below: npm's cache is
        # content-addressed (integrity-checked tarballs), so a hit is always
        # safe to reuse, and SCRIPT_DIR persists across the several
        # lineaje-verify.sh invocations veecli makes — WORKDIR does not.
        NPM_CACHE_DIR="${SCRIPT_DIR}/third_party/npm-verify-cache"
        if ! mkdir -p "$NPM_CACHE_DIR" 2>/dev/null; then
            NPM_CACHE_DIR="${WORKDIR}/npm-cache"
            mkdir -p "$NPM_CACHE_DIR"
        fi
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
    java)
        MVN_SETTINGS_ARGS=()
        if [[ "$CONNECT_TO_FORTKNOX" = "true" ]]; then
            if [[ -f "$MAVEN_SETTINGS" ]]; then
                MVN_SETTINGS_ARGS=(-s "$MAVEN_SETTINGS")
                log_info "Using maven settings: ${MAVEN_SETTINGS}"
            else
                log_error "lineaje-verify-settings.xml not found; GOS-rebuilt artifacts will not resolve"
            fi
        else
            log_info "connect_to_fortknox=false — resolving Java dependencies from Maven Central only; Lineaje-rebuilt packages will not resolve and their patches will be rejected"
        fi

        # A fresh -Dmaven.repo.local per invocation means every patched
        # component re-downloads the same Maven-core plugins (compiler,
        # resources, surefire, ...) and shared dependencies from scratch — for
        # a fix plan touching several components that's the same download
        # repeated several times over. Maven artifacts are immutable per
        # version (the ${revision} dummy aside, nothing here is a SNAPSHOT), so
        # a cache hit is always safe to reuse. SCRIPT_DIR (the veecli dir) is
        # stable for the whole job — including across the several separate
        # lineaje-verify.sh invocations veecli makes, one per patched component
        # — unlike WORKDIR, which is a fresh mktemp per invocation. Falls back
        # to WORKDIR when SCRIPT_DIR isn't writable (e.g. run by hand from a
        # read-only checkout).
        M2_REPO="${SCRIPT_DIR}/third_party/mvn-repo-cache"
        if ! mkdir -p "$M2_REPO" 2>/dev/null; then
            M2_REPO="${WORKDIR}/m2-repo"
            mkdir -p "$M2_REPO"
        fi
        log_info "Using Maven local repository cache: ${M2_REPO}"

        reconstruct_build_root

        log_info "Searching recursively for pom.xml under ${BUILD_ROOT}"
        ALL_POMS=()
        while IFS= read -r file; do
            ALL_POMS+=("$file")
        done < <(find "${BUILD_ROOT}" -type f -name "pom.xml" -not -path "*/target/*" 2>/dev/null)

        # Only the root pom of each project is built — a pom nested under another
        # pom's directory is treated as a module of that reactor, not a separate
        # project, so it is built as part of its root rather than standalone
        # (standalone would fail to resolve sibling-module dependencies that are
        # only ever produced by the reactor, not installed to the repo cache).
        POM_FILES=()
        if [[ "${#ALL_POMS[@]}" -gt 0 ]]; then
            for pom in "${ALL_POMS[@]}"; do
                pom_dir="$(dirname "$pom")"
                nested=0
                for other in "${ALL_POMS[@]}"; do
                    [[ "$other" == "$pom" ]] && continue
                    other_dir="$(dirname "$other")"
                    case "$pom_dir" in
                        "$other_dir"/*) nested=1; break ;;
                    esac
                done
                [[ "$nested" -eq 0 ]] && POM_FILES+=("$pom")
            done
        fi

        if [[ "${#POM_FILES[@]}" -eq 0 ]]; then
            log_info "No pom.xml found."
        else
            FOUND_ANY_MANIFEST=1
            log_info "Found ${#POM_FILES[@]} root pom.xml file(s):"
            for f in "${POM_FILES[@]}"; do
                log_info "  - ${f}"
            done

            for pom in "${POM_FILES[@]}"; do
                pom_dir="$(dirname "${pom}")"
                JAVA_PROJECT_DIRS+=("$pom_dir")

                if [[ -x "${pom_dir}/mvnw" ]]; then
                    MVN_CMD="${pom_dir}/mvnw"
                    log_info "Using project wrapper: ${MVN_CMD}"
                elif [[ -n "$MVN_BIN_DIR" && -x "${MVN_BIN_DIR}/mvn" ]]; then
                    MVN_CMD="${MVN_BIN_DIR}/mvn"
                    log_info "Using pinned Maven: ${MVN_CMD}"
                elif command -v mvn >/dev/null 2>&1; then
                    MVN_CMD="mvn"
                    log_info "Using Maven from PATH"
                else
                    log_error "No Maven available for ${pom_dir} (no wrapper, no --mvn-bin-dir, nothing on PATH)"
                    ANY_INSTALL_FAILED=1
                    continue
                fi

                # A pom using ${revision} with no default property fails to resolve
                # on its own; supply a dummy value just to let resolve/compile run.
                REVISION_ARGS=()
                if grep -q '\${revision}' "$pom" 2>/dev/null && ! grep -q '<revision>' "$pom" 2>/dev/null; then
                    REVISION_ARGS=(-Drevision=0.0.0-SNAPSHOT)
                    log_info "pom uses \${revision} with no default — passing -Drevision=0.0.0-SNAPSHOT"
                fi

                # test-compile alone resolves the full dependency graph (direct and
                # transitive, same as a standalone `dependency:resolve` would) because
                # it needs the complete classpath to compile against. A separate
                # `dependency:resolve` step beforehand was tried and dropped: unlike
                # test-compile, it does not participate in the reactor, so it
                # false-rejects any multi-module project where one module depends on
                # a sibling module's artifact that only the reactor (not the repo
                # cache) knows how to satisfy.
                mvn_log="${WORKDIR}/mvn_compile.log"
                : > "$mvn_log"
                log_info "Running: mvn test-compile (cwd=${pom_dir})"
                if (cd "${pom_dir}" && "${MVN_CMD}" -B -q \
                        "${MVN_SETTINGS_ARGS[@]+"${MVN_SETTINGS_ARGS[@]}"}" \
                        "${REVISION_ARGS[@]+"${REVISION_ARGS[@]}"}" \
                        -Dmaven.repo.local="${M2_REPO}" test-compile >"$mvn_log" 2>&1); then
                    log_info "mvn test-compile succeeded for ${pom}"
                else
                    log_error "mvn test-compile FAILED for ${pom}"
                    print_redacted_log "$mvn_log"
                    ANY_INSTALL_FAILED=1
                fi
            done
        fi

        # ── Gradle ────────────────────────────────────────────────────────────
        # Same BUILD_ROOT as Maven (reconstructed above). Handled independently of
        # pom.xml, so a directory carrying both build files gets both verified.
        GRADLE_INIT_ARGS=()
        if [[ "$CONNECT_TO_FORTKNOX" = "true" ]]; then
            if [[ -f "$GRADLE_INIT" ]]; then
                GRADLE_INIT_ARGS=(--init-script "$GRADLE_INIT")
                log_info "Using gradle init script: ${GRADLE_INIT}"
            else
                log_error "lineaje-verify-init.gradle not found; GOS-rebuilt artifacts will not resolve"
            fi
        else
            log_info "connect_to_fortknox=false — resolving Gradle dependencies from the project's own repositories only; Lineaje-rebuilt packages will not resolve and their patches will be rejected"
        fi

        # Same reasoning as the Maven repo cache: one stable GRADLE_USER_HOME
        # under SCRIPT_DIR is reused across the several invocations veecli makes
        # (one per patched component) and across workflow runs. Gradle's cache is
        # content-addressed, so reuse is safe. Falls back to WORKDIR when
        # SCRIPT_DIR is not writable.
        GRADLE_HOME_DIR="${SCRIPT_DIR}/third_party/gradle-verify-home"
        if ! mkdir -p "$GRADLE_HOME_DIR" 2>/dev/null; then
            GRADLE_HOME_DIR="${WORKDIR}/gradle-home"
            mkdir -p "$GRADLE_HOME_DIR"
        fi
        log_info "Using Gradle user home: ${GRADLE_HOME_DIR}"

        # Every dir that holds a settings or build script is a candidate; only the
        # outermost of each nest is built. Subprojects, buildSrc and included
        # modules sit under their root's directory and are built as part of it —
        # building them standalone would fail to resolve project(":sibling")
        # dependencies only the root build can satisfy.
        ALL_GRADLE_DIRS=()
        while IFS= read -r file; do
            ALL_GRADLE_DIRS+=("$(dirname "$file")")
        done < <(find "${BUILD_ROOT}" -type f \( -name "settings.gradle" -o -name "settings.gradle.kts" \
                    -o -name "build.gradle" -o -name "build.gradle.kts" \) \
                    -not -path "*/build/*" -not -path "*/.gradle/*" -not -path "*/node_modules/*" 2>/dev/null | sort -u)

        GRADLE_ROOTS=()
        if [[ "${#ALL_GRADLE_DIRS[@]}" -gt 0 ]]; then
            while IFS= read -r gdir; do
                [[ -n "$gdir" ]] || continue
                nested=0
                for other in "${GRADLE_ROOTS[@]+"${GRADLE_ROOTS[@]}"}"; do
                    case "$gdir" in
                        "$other"/*) nested=1; break ;;
                    esac
                done
                [[ "$nested" -eq 0 ]] && GRADLE_ROOTS+=("$gdir")
            done < <(printf '%s\n' "${ALL_GRADLE_DIRS[@]}" | sort -u)
        fi

        if [[ "${#GRADLE_ROOTS[@]}" -eq 0 ]]; then
            log_info "No Gradle build found."
        else
            log_info "Found ${#GRADLE_ROOTS[@]} root Gradle build(s):"
            for f in "${GRADLE_ROOTS[@]}"; do
                log_info "  - ${f}"
            done

            # Major version of the JDK on PATH (JAVA_HOME's bin is prepended by the
            # action), used to pick a Gradle that can actually run on it.
            JDK_MAJOR="$(java -version 2>&1 | sed -n '1s/.*version "\([0-9]*\)\.\{0,1\}\([0-9]*\).*/\1 \2/p' | awk '{print ($1==1)?$2:$1}')"
            case "${JDK_MAJOR:-}" in
                ''|*[!0-9]*) GRADLE_DEFAULT="8.14.4" ;;
                *)
                    if   [[ "$JDK_MAJOR" -le 16 ]]; then GRADLE_DEFAULT="7.6.6"
                    elif [[ "$JDK_MAJOR" -le 23 ]]; then GRADLE_DEFAULT="8.14.4"
                    else                                  GRADLE_DEFAULT="9.2.1"
                    fi ;;
            esac

            for gdir in "${GRADLE_ROOTS[@]}"; do
                # Android builds need the Android SDK and plugin, neither of which
                # this runner has — skipped with a warning rather than rejected, so
                # an otherwise valid patch is not blocked by tooling we cannot run.
                if grep -qsE 'com\.android\.(application|library)|com\.android\.tools\.build' \
                        "${gdir}"/build.gradle "${gdir}"/build.gradle.kts "${gdir}"/settings.gradle "${gdir}"/settings.gradle.kts 2>/dev/null; then
                    log_info "WARNING - ${gdir} is an Android build; skipping Gradle verification"
                    continue
                fi

                FOUND_ANY_MANIFEST=1
                GRADLE_PROJECT_DIRS+=("$gdir")

                if [[ -x "${gdir}/gradlew" ]]; then
                    GRADLE_CMD="${gdir}/gradlew"
                    log_info "Using project wrapper: ${GRADLE_CMD}"
                else
                    GRADLE_CMD=""
                    if [[ -n "$GRADLE_INSTALL_DIR" && -x "${GRADLE_INSTALL_DIR}/gradle-${GRADLE_DEFAULT}/bin/gradle" ]]; then
                        GRADLE_CMD="${GRADLE_INSTALL_DIR}/gradle-${GRADLE_DEFAULT}/bin/gradle"
                        log_info "Using pinned Gradle ${GRADLE_DEFAULT} (JDK ${JDK_MAJOR:-unknown}): ${GRADLE_CMD}"
                    elif command -v gradle >/dev/null 2>&1; then
                        GRADLE_CMD="gradle"
                        log_info "Using Gradle from PATH"
                    else
                        log_error "No Gradle available for ${gdir} (no wrapper, no install under --gradle-install-dir, nothing on PATH)"
                        ANY_INSTALL_FAILED=1
                        continue
                    fi
                fi

                # compileJava + compileTestJava resolve the full compile and test
                # classpaths, same idea as `mvn test-compile`: resolution failures
                # (an unpublished pin) fail the build. The `dependencies` task is
                # deliberately not used — it prints unresolved dependencies
                # without failing. No test execution.
                gradle_log="${WORKDIR}/gradle_compile.log"
                : > "$gradle_log"
                log_info "Running: gradle compileJava compileTestJava (cwd=${gdir})"
                if (cd "${gdir}" && GRADLE_USER_HOME="$GRADLE_HOME_DIR" "${GRADLE_CMD}" \
                        --no-daemon --console=plain -q \
                        "${GRADLE_INIT_ARGS[@]+"${GRADLE_INIT_ARGS[@]}"}" \
                        compileJava compileTestJava >"$gradle_log" 2>&1); then
                    log_info "gradle compile succeeded for ${gdir}"
                else
                    log_error "gradle compile FAILED for ${gdir}"
                    print_redacted_log "$gradle_log"
                    ANY_INSTALL_FAILED=1
                fi
            done
        fi
        ;;
    dotnet)
        if [[ -n "$DOTNET_BIN_DIR" && -d "$DOTNET_BIN_DIR" ]]; then
            export DOTNET_ROOT="$DOTNET_BIN_DIR"
            export PATH="${DOTNET_BIN_DIR}:${PATH}"
        fi
        export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
        if ! command -v dotnet >/dev/null 2>&1; then
            log_error "dotnet not found (dotnet bin directory: ${DOTNET_BIN_DIR:-not provided})."
            exit 1
        fi

        # The nuget.config reads its password from %ARTIFACTORY_NUGET_TOKEN%.
        # veecli should export that into the hook's environment; fall back to
        # the registry token it is documented to export as well.
        : "${ARTIFACTORY_NUGET_TOKEN:=${GOS_PREMIUM_REGISTRY_TOKEN:-}}"
        export ARTIFACTORY_NUGET_TOKEN

        # --configfile makes NuGet use ONLY that file (nuget.org + the GOS
        # feed, see templates/nuget.config); --source on its own overrides the
        # configured sources the same way for the public-only case.
        NUGET_ARGS=()
        if [[ "$CONNECT_TO_FORTKNOX" = "true" ]]; then
            if [[ -f "$NUGET_CONFIG" && -n "${ARTIFACTORY_NUGET_TOKEN}" ]]; then
                NUGET_ARGS=(--configfile "$NUGET_CONFIG")
                log_info "Using NuGet configuration: ${NUGET_CONFIG}"
            else
                log_error "lineaje-verify.nuget.config or ARTIFACTORY_NUGET_TOKEN missing; GOS-rebuilt packages will not resolve"
                NUGET_ARGS=(--source "https://api.nuget.org/v3/index.json")
            fi
        else
            NUGET_ARGS=(--source "https://api.nuget.org/v3/index.json")
            log_info "connect_to_fortknox=false — restoring .NET dependencies from nuget.org only; Lineaje-rebuilt packages will not resolve and their patches will be rejected"
        fi

        # Same reasoning as the Maven repo cache: NuGet packages are immutable
        # per version, so reuse is always safe, and SCRIPT_DIR persists across
        # the several lineaje-verify.sh invocations veecli makes — WORKDIR
        # does not.
        NUGET_PACKAGES_DIR="${SCRIPT_DIR}/third_party/nuget-verify-cache"
        if ! mkdir -p "$NUGET_PACKAGES_DIR" 2>/dev/null; then
            NUGET_PACKAGES_DIR="${WORKDIR}/nuget-packages"
            mkdir -p "$NUGET_PACKAGES_DIR"
        fi
        log_info "Using NuGet packages cache: ${NUGET_PACKAGES_DIR}"

        reconstruct_build_root

        # Decide what to restore. Restoring a project also restores its
        # ProjectReferences, so one entry per touched project is enough:
        #  - a project file in --task-dir (a .csproj/.fsproj/.vbproj whose
        #    PackageReference versions were patched) → restore that project;
        #  - Directory.Packages.props / Directory.Build.props in --task-dir
        #    (central package versions) → restore every project beneath that
        #    file's directory, since any of them may consume the bumped version.
        # packages.config (legacy) is not restorable with `dotnet restore` on
        # Linux, so it is not a target.
        TARGETS_FILE="${WORKDIR}/dotnet-targets.txt"
        : > "$TARGETS_FILE"
        while IFS= read -r file; do
            printf '%s\n' "${BUILD_ROOT}/${file#"${REPO_ROOT}"/}" >>"$TARGETS_FILE"
        done < <(find "${REPO_ROOT}" -type f \( -name "*.csproj" -o -name "*.fsproj" -o -name "*.vbproj" \) -not -path "*/bin/*" -not -path "*/obj/*" 2>/dev/null)
        while IFS= read -r file; do
            props_dir="$(dirname "${BUILD_ROOT}/${file#"${REPO_ROOT}"/}")"
            find "$props_dir" -type f \( -name "*.csproj" -o -name "*.fsproj" -o -name "*.vbproj" \) -not -path "*/bin/*" -not -path "*/obj/*" 2>/dev/null >>"$TARGETS_FILE"
        done < <(find "${REPO_ROOT}" -type f \( -name "Directory.Packages.props" -o -name "Directory.Build.props" \) 2>/dev/null)

        PROJECT_FILES=()
        while IFS= read -r file; do
            [[ -n "$file" && -f "$file" ]] && PROJECT_FILES+=("$file")
        done < <(sort -u "$TARGETS_FILE")

        if [[ "${#PROJECT_FILES[@]}" -eq 0 ]]; then
            log_info "No .NET project files to restore."
        else
            FOUND_ANY_MANIFEST=1
            log_info "Found ${#PROJECT_FILES[@]} .NET project file(s) to restore:"
            for f in "${PROJECT_FILES[@]}"; do
                log_info "  - ${f}"
            done

            for proj in "${PROJECT_FILES[@]}"; do
                DOTNET_PROJECT_DIRS+=("$(dirname "$proj")")
                # No --locked-mode, and RestoreLockedMode is forced off: a
                # patched version bump legitimately disagrees with an existing
                # packages.lock.json, which would otherwise reject every patch
                # (NU1004) for a project that opts in to locked restores.
                dotnet_log="${WORKDIR}/dotnet_restore.log"
                : > "$dotnet_log"
                log_info "Running: dotnet restore ${proj}"
                if dotnet restore "${proj}" \
                        "${NUGET_ARGS[@]}" \
                        --packages "${NUGET_PACKAGES_DIR}" \
                        -p:RestoreLockedMode=false >"$dotnet_log" 2>&1; then
                    log_info "dotnet restore succeeded for ${proj}"
                else
                    log_error "dotnet restore FAILED for ${proj}. Redacted output follows:"
                    print_redacted_log "$dotnet_log"
                    ANY_INSTALL_FAILED=1
                fi
            done
        fi
        ;;
    go|golang)
        # No GOS/Fortknox proxy for Go modules exists yet — always the public
        # proxy, regardless of --connect-to-fortknox. Revisit once one exists
        # (mirror the java/node case: a registry URL plus credentials wired
        # through _gos_premium_env).
        if [[ "$CONNECT_TO_FORTKNOX" = "true" ]]; then
            log_info "connect_to_fortknox=true requested, but no GOS premium Go proxy is configured yet — using the public Go proxy only"
        else
            log_info "connect_to_fortknox=false — using the public Go proxy only (same as today's default; no-op for Go)"
        fi
        GOPROXY_VALUE="https://proxy.golang.org,direct"

        # Same reasoning as the Maven repo cache: a fresh GOMODCACHE/GOCACHE per
        # invocation means every patched module re-downloads the same shared
        # dependencies from scratch. Go modules are content-addressed and
        # immutable once published, so a cache hit is always safe to reuse.
        GOMODCACHE_DIR="${SCRIPT_DIR}/third_party/go-mod-cache"
        if ! mkdir -p "$GOMODCACHE_DIR" 2>/dev/null; then
            GOMODCACHE_DIR="${WORKDIR}/go-mod-cache"
            mkdir -p "$GOMODCACHE_DIR"
        fi
        GOCACHE_DIR="${SCRIPT_DIR}/third_party/go-build-cache"
        if ! mkdir -p "$GOCACHE_DIR" 2>/dev/null; then
            GOCACHE_DIR="${WORKDIR}/go-build-cache"
            mkdir -p "$GOCACHE_DIR"
        fi
        log_info "Using Go module cache: ${GOMODCACHE_DIR}"
        log_info "Using Go build cache: ${GOCACHE_DIR}"

        reconstruct_build_root

        log_info "Searching recursively for go.mod under ${BUILD_ROOT}"
        GO_MOD_FILES=()
        while IFS= read -r file; do
            GO_MOD_FILES+=("$file")
        done < <(find "${BUILD_ROOT}" -type f -name "go.mod" -not -path "*/vendor/*" 2>/dev/null)

        if [[ "${#GO_MOD_FILES[@]}" -eq 0 ]]; then
            log_info "No go.mod found."
        else
            FOUND_ANY_MANIFEST=1
            log_info "Found ${#GO_MOD_FILES[@]} go.mod file(s):"
            for f in "${GO_MOD_FILES[@]}"; do
                log_info "  - ${f}"
            done

            for gomod in "${GO_MOD_FILES[@]}"; do
                mod_dir="$(dirname "${gomod}")"

                # "go build ./..." over a directory with no .go files at all
                # matches zero packages and exits 0 — a silent false pass that
                # verified nothing. That's the exact shape of the --task-dir-is-
                # only-the-manifest problem --repo-root exists to fix; if it
                # still happens (missing/broken --repo-root), fail loud instead
                # of reporting success for a build that never actually ran.
                if ! find "$mod_dir" -type f -name "*.go" -not -path "*/vendor/*" -print -quit 2>/dev/null | grep -q .; then
                    log_error "No .go source files found under ${mod_dir} — cannot verify this go.mod (likely missing or unusable --repo-root). Treating as failed rather than reporting a no-op success."
                    ANY_INSTALL_FAILED=1
                    continue
                fi

                if [[ -n "$GO_BIN_DIR" && -x "${GO_BIN_DIR}/go" ]]; then
                    GO_CMD="${GO_BIN_DIR}/go"
                    log_info "Using pinned Go: ${GO_CMD}"
                elif command -v go >/dev/null 2>&1; then
                    GO_CMD="go"
                    log_info "Using Go from PATH"
                else
                    log_error "No Go available for ${mod_dir} (no --go-bin-dir, nothing on PATH)"
                    ANY_INSTALL_FAILED=1
                    continue
                fi

                # A vendor/ directory implies -mod=vendor: no network call at
                # all, so GOPROXY/the lack of a GOS proxy is moot for this module.
                VENDOR_ARGS=()
                if [[ -d "${mod_dir}/vendor" ]]; then
                    VENDOR_ARGS=(-mod=vendor)
                    log_info "vendor/ directory detected — building in vendor mode (no network)"
                fi

                # go build only ever writes an output file into mod_dir itself
                # (never a subdirectory) and only when "./..." resolves to
                # exactly one main package — everything else (library-only
                # modules, multiple packages) compiles and discards, writing
                # nothing. Rather than relying on that rule (and -o forcing an
                # error when there's no main package to write — tried and
                # dropped), snapshot mod_dir's top-level files before and after
                # and remove whatever new executable shows up.
                BEFORE_FILES="$(find "$mod_dir" -maxdepth 1 -type f 2>/dev/null | sort)"

                go_log="${WORKDIR}/go_build.log"
                : > "$go_log"
                log_info "Running: go build ./... (cwd=${mod_dir})"
                # [debug] output streamed live (redacted), same temporary
                # verbosity as the java case — revert once Go support is done
                # being tested.
                if (cd "${mod_dir}" && GOPROXY="$GOPROXY_VALUE" GOMODCACHE="$GOMODCACHE_DIR" GOCACHE="$GOCACHE_DIR" \
                        "${GO_CMD}" build "${VENDOR_ARGS[@]+"${VENDOR_ARGS[@]}"}" ./... 2>&1 \
                        | tee "$go_log" \
                        | sed -E 's#(https?://)[^[:space:]]*@#\1***:***@#g'); then
                    log_info "go build succeeded for ${gomod}"
                else
                    log_error "go build FAILED for ${gomod} (see output above)"
                    ANY_INSTALL_FAILED=1
                fi

                while IFS= read -r built_file; do
                    [[ -n "$built_file" ]] || continue
                    if [[ -x "$built_file" ]] && ! grep -qxF "$built_file" <<<"$BEFORE_FILES"; then
                        log_info "Removing build output written to the module dir: ${built_file}"
                        rm -f "$built_file"
                    fi
                done <<<"$(find "$mod_dir" -maxdepth 1 -type f 2>/dev/null | sort)"
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
