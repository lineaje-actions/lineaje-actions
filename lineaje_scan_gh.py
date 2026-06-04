#!/usr/bin/env python3
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

"""
lineaje_scan.py — unified Lineaje scan orchestrator for container images and source code.

Scan type is selected automatically:
  - Provide --image              → container image scan
  - Provide --src-folder         → source code scan (Maven / Gradle / Python / Node)

Flow (both modes):
  1. Exchange refresh token → build config.json
  2. Run veecli collect
  3. Parse SBOM job ID from veecli output
  4. Poll SCIM until terminal state (ready for review / failed)
  5. Fetch and display vulnerability summary

Usage — image scan:
    python3 lineaje_scan.py \
        --image docker.io/library/python:3.8-slim \
        --name MyProject --version 1.0 --org-name "My Org" \
        --refresh-token <token> --config-orig /path/to/config-orig.json \
        --veecli /path/to/veecli

Usage — source scan:
    python3 lineaje_scan.py \
        --src-folder /path/to/source \
        --src-url https://github.com/org/repo --matching-ref main \
        --name MyProject --version 1.0 --org-name "My Org" \
        --refresh-token <token> --config-orig /path/to/config-orig.json \
        --veecli /path/to/veecli
"""

import argparse
import base64
import copy
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

import requests

os.environ["PYTHONUNBUFFERED"] = "1"

DEFAULT_CONFIG = Path.home() / "veecli" / "config.json"
THIRD_PARTY = Path("/opt/veecli/third_party/linux")
DEFAULT_GPT_HOST = "https://lineaje-gpt-service.v2.prod.veedna.com"

# ── Java / Maven / Gradle runtime data ────────────────────────────────────────

OPENJDK_RELEASES = [
    # (dir_name, url_template_with_{arch}, x64_only)
    ("openjdk-8_linux-amd64",    "https://download.java.net/openjdk/jdk8u42/ri/openjdk-8u42-b03-linux-{arch}-14_jul_2022.tar.gz",                             True),
    ("openjdk-9.0.4_linux-amd64",  "https://download.java.net/java/GA/jdk9/9.0.4/binaries/openjdk-9.0.4_linux-{arch}_bin.tar.gz",                            True),
    ("openjdk-10.0.2_linux-amd64", "https://download.java.net/java/GA/jdk10/10.0.2/19aef61b38124481863b1413dce1855f/13/openjdk-10.0.2_linux-{arch}_bin.tar.gz", True),
    ("openjdk-11.0.2_linux-amd64", "https://download.java.net/java/GA/jdk11/9/GPL/openjdk-11.0.2_linux-{arch}_bin.tar.gz",                                   True),
    ("openjdk-12.0.2_linux-amd64", "https://download.java.net/java/GA/jdk12.0.2/e482c34c86bd4bf8b56c0b35558996b9/10/GPL/openjdk-12.0.2_linux-{arch}_bin.tar.gz", True),
    ("openjdk-13.0.2_linux-amd64", "https://download.java.net/java/GA/jdk13.0.2/d4173c853231432d94f001e99d882ca7/8/GPL/openjdk-13.0.2_linux-{arch}_bin.tar.gz",  True),
    ("openjdk-14.0.2_linux-amd64", "https://download.java.net/java/GA/jdk14.0.2/205943a0976c4ed48cb16f1043c5c647/12/GPL/openjdk-14.0.2_linux-{arch}_bin.tar.gz", True),
    ("openjdk-15.0.2_linux-amd64", "https://download.java.net/java/GA/jdk15.0.2/0d1cfde4252546c6931946de8db48ee2/7/GPL/openjdk-15.0.2_linux-{arch}_bin.tar.gz",  False),
    ("openjdk-16.0.2_linux-amd64", "https://download.java.net/java/GA/jdk16.0.2/d4a915d82b4c4fbb9bde534da945d746/7/GPL/openjdk-16.0.2_linux-{arch}_bin.tar.gz",  False),
    ("openjdk-17.0.2_linux-amd64", "https://download.java.net/java/GA/jdk17.0.2/dfd4a8d0985749f896bed50d7138ee7f/8/GPL/openjdk-17.0.2_linux-{arch}_bin.tar.gz",  False),
    ("openjdk-18.0.2_linux-amd64", "https://download.java.net/java/GA/jdk18.0.2/f6ad4b4450fd4d298113270ec84f30ee/9/GPL/openjdk-18.0.2_linux-{arch}_bin.tar.gz",  False),
    ("openjdk-19.0.1_linux-amd64", "https://download.java.net/java/GA/jdk19.0.1/afdd2e245b014143b62ccb916125e3ce/10/GPL/openjdk-19.0.1_linux-{arch}_bin.tar.gz", False),
    ("openjdk-20.0.2_linux-amd64", "https://download.java.net/java/GA/jdk20.0.2/6e380f22cbe7469fa75fb448bd903d8e/9/GPL/openjdk-20.0.2_linux-{arch}_bin.tar.gz",   False),
    ("openjdk-21.0.2_linux-amd64", "https://download.java.net/java/GA/jdk21.0.2/f2283984656d49d69e91c558476027ac/13/GPL/openjdk-21.0.2_linux-{arch}_bin.tar.gz",  False),
    ("openjdk-22.0.2_linux-amd64", "https://download.java.net/java/GA/jdk22.0.2/c9ecb94cd31b495da20a27d4581645e8/9/GPL/openjdk-22.0.2_linux-{arch}_bin.tar.gz",   False),
    ("openjdk-23.0.2_linux-amd64", "https://download.java.net/java/GA/jdk23.0.2/6da2a6609d6e406f85c491fcb119101b/7/GPL/openjdk-23.0.2_linux-{arch}_bin.tar.gz",   False),
    ("openjdk-24.0.2_linux-amd64", "https://download.java.net/java/GA/jdk24.0.2/fdc5d0102fe0414db21410ad5834341f/12/GPL/openjdk-24.0.2_linux-{arch}_bin.tar.gz",  False),
    ("openjdk-25.0.2_linux-amd64", "https://download.java.net/java/GA/jdk25.0.2/b1e0dfa218384cb9959bdcb897162d4e/10/GPL/openjdk-25.0.2_linux-{arch}_bin.tar.gz",  False),
]

MAVEN_VERSION = "3.9.16"
MAVEN_URL = f"https://dlcdn.apache.org/maven/maven-3/{MAVEN_VERSION}/binaries/apache-maven-{MAVEN_VERSION}-bin.tar.gz"
MAVEN_DIR = f"maven-{MAVEN_VERSION}"

GRADLE_VERSIONS = [
    "8.9", "8.6", "8.4", "8.2", "8.1.1", "8.0.2",
    "7.6.1", "7.5.1", "7.4.2",
    "6.9.1", "6.3",
    "5.6.4", "5.5.1",
    "4.9",
]

# ── Python runtime data ────────────────────────────────────────────────────────

PYTHON_APT_DEPS = [
    "git", "apt-utils", "pkg-config", "tar", "unzip", "wget", "curl",
    "build-essential", "libssl-dev", "libffi-dev", "python3-pip",
    "libbz2-dev", "libpq-dev", "libsqlite3-dev", "python3-venv",
    "liblzma-dev",   # required for _lzma module; pip uses lzma to extract some packages
    "zlib1g-dev",    # required for zlib module; needed for pip wheel extraction
]

PYTHON_RELEASES = [
    # (version, dir_name, binary_name)
    ("3.14.5", "python314", "python3.14"),
    ("3.13.3", "python313", "python3.13"),
    ("3.12.9", "python312", "python3.12"),
    ("3.11.8", "python311", "python3.11"),
    ("3.10.8", "python310", "python3.10"),
    ("3.9.15",  "python39",  "python3.9"),
    ("3.8.15",  "python38",  "python3.8"),
    ("3.7.15",  "python37",  "python3.7"),
    ("3.6.15",  "python36",  "python3.6"),  # requires pip-python36.patch from veecli
]

PIPDEPTREE_VERSION = "2.3.3"

# ── Node.js runtime data ───────────────────────────────────────────────────────

NODE_VERSIONS = ["16.20.2", "18.19.0", "20.18.0", "21.4.0", "22.11.0", "24.15.0", "26.2.0"]


def log(level: str, msg: str):
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)


# ── Java / Maven / Gradle runtime setup ───────────────────────────────────────

def _detect_arch() -> str:
    machine = platform.machine()
    if machine == "x86_64":
        return "x64"
    if machine == "aarch64":
        return "aarch64"
    sys.exit(f"[error] Unsupported architecture: {machine}")


def _download(url: str, dest: Path):
    log("info", f"Downloading {Path(url).name}")
    try:
        urllib.request.urlretrieve(url, dest)
    except Exception as e:
        sys.exit(f"[error] Failed to download {url}: {e}")


def _extract_tar_strip1(archive: Path, dest: Path):
    """Extract a .tar.gz or .tar.xz, dropping the top-level directory (--strip-components=1)."""
    dest.mkdir(parents=True, exist_ok=True)
    _kwargs = {"filter": "data"} if sys.version_info >= (3, 12) else {}
    with tarfile.open(archive, "r:*") as tf:
        for member in tf.getmembers():
            slash = member.name.find("/")
            if slash == -1:
                continue  # top-level dir entry itself
            member.name = member.name[slash + 1:]
            if not member.name:
                continue
            tf.extract(member, dest, **_kwargs)


def _extract_zip(archive: Path, dest: Path):
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(dest)


def setup_java_runtime(java_version: str):
    """Install a specific OpenJDK plus all Maven and all Gradle versions.

    java_version: Java major version to install (e.g. "17", "11").
                  All Maven and Gradle versions are always installed.
    """
    arch = _detect_arch()

    # ── Select the requested JDK ───────────────────────────────────────────────
    jdk_releases = [
        (d, u, x) for d, u, x in OPENJDK_RELEASES
        if d.startswith(f"openjdk-{java_version}")
    ]
    if not jdk_releases:
        available = sorted({d.split("-")[1].split(".")[0] for d, _, _ in OPENJDK_RELEASES})
        sys.exit(
            f"[error] No OpenJDK release found for Java {java_version!r}. "
            f"Available major versions: {', '.join(available)}"
        )

    log("info", f"Setting up Java runtime (arch: {arch})")
    log("info", f"JDK: {[d for d, _, _ in jdk_releases]}")
    log("info", f"Maven: {MAVEN_VERSION} + Gradle: all {len(GRADLE_VERSIONS)} versions")

    for dir_name, _, _ in jdk_releases:
        (THIRD_PARTY / dir_name).mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="lineaje-java-setup-") as tmp:

        tmp_path = Path(tmp)

        # ── Install OpenJDK versions ───────────────────────────────────────────
        for dir_name, url_tpl, x64_only in jdk_releases:
            if x64_only and arch != "x64":
                log("info", f"Skipping {dir_name} (x64 only, arch={arch})")
                continue

            dest = THIRD_PARTY / dir_name
            java_bin = dest / "bin" / "java"
            if java_bin.exists():
                log("info", f"Skipping {dir_name} — already installed")
                continue

            url = url_tpl.format(arch=arch)
            archive = tmp_path / Path(url).name
            _download(url, archive)
            _extract_tar_strip1(archive, dest)
            if java_bin.exists():
                log("info", f"Installed {dir_name}: {java_bin}")
            else:
                log("warn", f"java binary not found after extracting {dir_name}")
            archive.unlink(missing_ok=True)

        # ── Install Maven ──────────────────────────────────────────────────────
        dest = THIRD_PARTY / MAVEN_DIR
        dest.mkdir(parents=True, exist_ok=True)
        mvn_bin = dest / "bin" / "mvn"
        if mvn_bin.exists():
            log("info", f"Skipping Maven {MAVEN_VERSION} — already installed")
        else:
            archive = tmp_path / f"apache-maven-{MAVEN_VERSION}-bin.tar.gz"
            _download(MAVEN_URL, archive)
            _extract_tar_strip1(archive, dest)
            if mvn_bin.exists():
                mvn_bin.chmod(mvn_bin.stat().st_mode | 0o111)
                log("info", f"Installed Maven {MAVEN_VERSION}: {mvn_bin}")
            else:
                log("warn", "mvn binary not found after extraction")
            archive.unlink(missing_ok=True)

        # ── Install all Gradle versions ────────────────────────────────────────
        for gv in GRADLE_VERSIONS:
            gradle_bin = THIRD_PARTY / f"gradle-{gv}" / "bin" / "gradle"
            if gradle_bin.exists():
                log("info", f"Skipping Gradle {gv} — already installed")
                continue
            filename = f"gradle-{gv}-bin.zip"
            url = f"https://services.gradle.org/distributions/{filename}"
            archive = tmp_path / filename
            _download(url, archive)
            _extract_zip(archive, THIRD_PARTY)
            if gradle_bin.exists():
                gradle_bin.chmod(gradle_bin.stat().st_mode | 0o111)
                log("info", f"Installed Gradle {gv}: {gradle_bin}")
            else:
                log("warn", f"gradle binary not found after extracting {filename}")
            archive.unlink(missing_ok=True)

    log("info", "Java runtime setup complete")


def setup_python_runtime(version: str = ""):
    """Build and install Python from source into /opt/veecli/third_party/linux/.

    version: Python minor version to install (e.g. "3.11", "3.14"). Omit for all (3.6–3.14).

    Mirrors setup_python_scan.sh:
      1. apt-get install build dependencies
      2. For each version: download, extract, configure, make install
      3. Python 3.6 requires pip-python36.patch from /opt/veecli/scripts/
      4. pip install pipdeptree
      5. Clean up source trees and tarballs
    """
    if version:
        releases = [(v, d, b) for v, d, b in PYTHON_RELEASES if v.startswith(version)]
        if not releases:
            available = [v.rsplit(".", 1)[0] for v, _, _ in PYTHON_RELEASES]
            sys.exit(
                f"[error] Python {version!r} not available. "
                f"Available: {', '.join(available)}"
            )
    else:
        releases = PYTHON_RELEASES

    label = version or "3.6–3.14"
    log("info", f"Setting up Python {label} — this will take a while")

    # ── 1. System build dependencies ──────────────────────────────────────────
    log("info", "Installing apt build dependencies")
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    subprocess.run(["sudo", "apt-get", "update"], check=True, env=env)
    subprocess.run(
        ["sudo", "apt-get", "install", "-y"] + PYTHON_APT_DEPS,
        check=True, env=env,
    )

    # ── 2. Create target directories ──────────────────────────────────────────
    for _, dir_name, _ in releases:
        (THIRD_PARTY / dir_name).mkdir(parents=True, exist_ok=True)

    patch_file = Path("/opt/veecli/scripts/pip-python36.patch")

    with tempfile.TemporaryDirectory(prefix="lineaje-python-setup-") as tmp:
        tmp_path = Path(tmp)

        for version, dir_name, binary_name in releases:
            prefix = THIRD_PARTY / dir_name
            if (prefix / "bin" / binary_name).exists():
                log("info", f"Skipping Python {version} — already installed")
                continue
            tarball_name = f"Python-{version}.tgz"
            url = f"https://www.python.org/ftp/python/{version}/{tarball_name}"
            archive = tmp_path / tarball_name
            src_dir = tmp_path / f"Python-{version}"

            log("info", f"Downloading Python {version}")
            _download(url, archive)

            log("info", f"Extracting Python {version}")
            with tarfile.open(archive, "r:gz") as tf:
                tf.extractall(tmp_path)
            archive.unlink(missing_ok=True)

            # Python 3.6 requires a patch before building
            if version.startswith("3.6"):
                if patch_file.exists():
                    log("info", "Applying pip-python36.patch")
                    subprocess.run(
                        ["patch", "-p0", "-i", str(patch_file)],
                        cwd=tmp_path, check=True,
                    )
                else:
                    log("warn", f"pip-python36.patch not found at {patch_file} — skipping patch")

            log("info", f"Building Python {version} (configure + make install)")
            subprocess.run(
                ["./configure", f"--prefix={prefix}"],
                cwd=src_dir, check=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["make", "install"],
                cwd=src_dir, check=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )

            python_bin = prefix / "bin" / binary_name
            if python_bin.exists():
                log("info", f"Installed Python {version}: {python_bin}")
            else:
                log("warn", f"{binary_name} not found after installing Python {version}")

            shutil.rmtree(src_dir, ignore_errors=True)

    # ── 3. Install pipdeptree ──────────────────────────────────────────────────
    # Install into each Python version's own environment so veecli can find it
    # as a "tool provider" at third_party/linux/pythonXYZ/bin/pipdeptree.
    for _, dir_name, binary_name in releases:
        python_bin = THIRD_PARTY / dir_name / "bin" / binary_name
        if python_bin.exists():
            log("info", f"Installing pipdeptree=={PIPDEPTREE_VERSION} for {binary_name}")
            subprocess.run(
                [str(python_bin), "-m", "pip", "install", f"pipdeptree=={PIPDEPTREE_VERSION}"],
                check=True,
            )
        else:
            log("warn", f"Skipping pipdeptree install — {python_bin} not found")

    # Also install into the action venv (activated by action.yml step 9) so
    # veecli always has a local-env pipdeptree fallback. Without this fallback
    # veecli proceeds with a nil python context and crashes.
    log("info", f"Installing pipdeptree=={PIPDEPTREE_VERSION} into action venv")
    subprocess.run(
        ["pip", "install", f"pipdeptree=={PIPDEPTREE_VERSION}"],
        check=True,
    )

    # ── 4. Add installed Python bin dirs to PATH ──────────────────────────────
    # veecli discovers the Python runtime by searching PATH for python3.XX.
    # Versions we build from source (e.g. python3.12) are only under
    # third_party/linux/pythonXYZ/bin/ which is not in PATH by default.
    # Adding them here means the os.environ inherited by the veecli subprocess
    # will contain the correct binary, so veecli resolves requires-python
    # constraints like ">=3.12" to our installed binary rather than falling
    # back to the system Python (3.9 / 3.13 depending on the runner).
    for _, dir_name, binary_name in releases:
        bin_dir = str(THIRD_PARTY / dir_name / "bin")
        if (THIRD_PARTY / dir_name / "bin" / binary_name).exists():
            path = os.environ.get("PATH", "")
            if bin_dir not in path.split(os.pathsep):
                os.environ["PATH"] = bin_dir + os.pathsep + path
                log("info", f"Added {bin_dir} to PATH")

    log("info", "Python runtime setup complete")


def setup_node_runtime(version: str = ""):
    """Install Node.js into /opt/veecli/third_party/linux/.

    version: Node.js major or full version to install (e.g. "18", "16.20.2").
             Omit to install all (16, 18, 21).

    Mirrors setup_npm_scan.sh. Note: Node uses 'arm64' for aarch64, not 'aarch64'.
    """
    if version:
        versions_to_install = [v for v in NODE_VERSIONS if v == version or v.startswith(version + ".")]
        if not versions_to_install:
            available_majors = [v.split(".")[0] for v in NODE_VERSIONS]
            sys.exit(
                f"[error] Node.js {version!r} not available. "
                f"Available: {', '.join(NODE_VERSIONS)} (or by major: {', '.join(available_majors)})"
            )
    else:
        versions_to_install = NODE_VERSIONS

    # Node arch key differs from Java: aarch64 → arm64
    machine = platform.machine()
    if machine == "x86_64":
        arch = "x64"
    elif machine == "aarch64":
        arch = "arm64"
    else:
        sys.exit(f"[error] Unsupported architecture for Node.js: {machine}")

    label = version or ", ".join(NODE_VERSIONS)
    log("info", f"Setting up Node.js {label} (arch: {arch})")

    with tempfile.TemporaryDirectory(prefix="lineaje-node-setup-") as tmp:
        tmp_path = Path(tmp)

        for version in versions_to_install:
            dest = THIRD_PARTY / f"node-{version}"
            npm_bin = dest / "bin" / "npm"
            if npm_bin.exists():
                log("info", f"Skipping Node.js {version} — already installed")
                continue
            filename = f"node-v{version}-linux-{arch}.tar.xz"
            url = f"https://nodejs.org/dist/v{version}/{filename}"
            archive = tmp_path / filename

            dest.mkdir(parents=True, exist_ok=True)
            _download(url, archive)
            _extract_tar_strip1(archive, dest)
            archive.unlink(missing_ok=True)

            if npm_bin.exists():
                log("info", f"Installed Node.js {version}: {npm_bin}")
            else:
                log("warn", f"npm not found after extracting Node.js {version}")

    log("info", "Node.js runtime setup complete")


# ── Auth / config ──────────────────────────────────────────────────────────────

def fetch_access_token(auth_service: str, refresh_token: str) -> str:
    url = (
        f"{auth_service.rstrip('/')}"
        "/lineajeidentity/api/v1/auth/native/renew-access-token"
    )
    log("info", f"Exchanging refresh token at {url}")
    log("debug", f"Refresh token (first 20): {refresh_token[:20]}...")

    try:
        resp = requests.post(url, params={"refreshToken": refresh_token}, timeout=30)
    except requests.RequestException as e:
        sys.exit(f"[error] Failed to reach identity service: {e}")

    log("debug", f"Identity service response: HTTP {resp.status_code}")

    if resp.status_code == 401:
        sys.exit("[error] Refresh token is invalid or expired (401)")
    if resp.status_code == 400:
        sys.exit(f"[error] Bad request to identity service (400): {resp.text[:300]}")
    if resp.status_code != 200:
        sys.exit(f"[error] Identity service returned {resp.status_code}: {resp.text[:200]}")

    token = resp.text.strip().strip('"').strip("'")
    if token.startswith("{"):
        try:
            data = json.loads(token)
            token = (
                data.get("access_token") or data.get("accessToken") or data.get("token") or ""
            )
        except json.JSONDecodeError:
            pass
    if not token:
        sys.exit("[error] Empty access token from identity service")

    log("info", "Access token obtained")
    return token


def _expiry_from_jwt(token: str) -> str:
    try:
        part = token.split(".")[1]
        part += "=" * (4 - len(part) % 4)
        payload = json.loads(base64.urlsafe_b64decode(part))
        exp = payload.get("exp", 0)
        if exp:
            return datetime.fromtimestamp(exp, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        pass
    return ""


def build_config(config_orig_path: str, refresh_token: str, output_path: str):
    orig = Path(config_orig_path)
    if not orig.exists():
        sys.exit(f"[error] config-orig.json not found: {orig}")
    with orig.open() as f:
        config_orig = json.load(f)

    auth_service = config_orig.get("LineajeAuthService", "").rstrip("/")
    if not auth_service:
        sys.exit("[error] LineajeAuthService not found in config-orig.json")

    access_token = fetch_access_token(auth_service, refresh_token)
    expiry = _expiry_from_jwt(access_token)
    if expiry:
        log("info", f"Token expires at {expiry}")

    config = {
        "AuthClient": {
            "DeviceCode": "DUMMY_DEVICE_CODE",
            "ExpiresIn": 43200,
            "AccessToken": access_token,
            "TimeOfExpiration": expiry or "2020-01-01T00:00:00Z",
            "RefreshToken": refresh_token,
            "CompanyID": "DUMMY_COMPANY_ID",
            "OrganizationID": "DUMMY_ORG_ID",
            "OrganizationName": "DUMMY_ORG",
            "CompanyDetails": {
                "id": 0,
                "created_date": "2020-01-01T00:00:00Z",
                "modified_date": "2020-01-01T00:00:00Z",
                "name": "DUMMY",
                "ext_organization_id": "DUMMY_ORG",
                "unique_id": "DUMMY_COMPANY_ID",
            },
            "RegisteredOrganizationID": "DUMMY_ORG_ID",
            "RegisteredOrganizationName": "DUMMY_ORG",
            "EmailID": "dummy@example.com",
        },
        **config_orig,
    }

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as f:
        json.dump(config, f, indent=2)
    log("info", f"config.json written to {out}")


def load_config(config_path: str) -> dict:
    path = Path(config_path)
    if not path.exists():
        sys.exit(f"[error] config.json not found: {path}")
    with path.open() as f:
        cfg = json.load(f)
    log("info", f"Config loaded — SCIMHost={cfg.get('SCIMHost', 'N/A')}")
    return cfg


def get_auth_token(cfg: dict) -> str:
    token = cfg.get("AuthClient", {}).get("AccessToken", "")
    if not token:
        sys.exit("[error] AccessToken not found in config.json")
    expiry_str = cfg.get("AuthClient", {}).get("TimeOfExpiration", "")
    if expiry_str:
        try:
            expiry = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
            if expiry <= datetime.now(timezone.utc):
                log("warn", f"Access token expired at {expiry_str} — veecli should have refreshed it")
        except ValueError:
            pass
    return token


def get_scim_host(cfg: dict) -> str:
    host = cfg.get("SCIMHost", "").rstrip("/")
    if not host:
        sys.exit("[error] SCIMHost not found in config.json")
    return host


def get_data_host(cfg: dict, override: str) -> str:
    if override:
        return override.rstrip("/")
    host = cfg.get("GraphQLServiceHost", "").rstrip("/")
    if not host:
        sys.exit("[error] GraphQLServiceHost not in config and --data-host not supplied")
    return host


def get_gpt_host(cfg: dict, override: str) -> str:
    if override:
        return override.rstrip("/")
    return cfg.get("GPTServiceHost", DEFAULT_GPT_HOST).rstrip("/")


def get_company_id_from_token(token: str) -> str:
    try:
        part = token.split(".")[1]
        part += "=" * (4 - len(part) % 4)
        payload = json.loads(base64.urlsafe_b64decode(part))
        cid = payload.get("user_metadata", {}).get("company_id", "")
        if cid:
            log("info", f"Extracted company_id from token: {cid}")
        return cid
    except Exception as e:
        log("warn", f"Could not decode company_id from token: {e}")
        return ""


# ── veecli config patching ────────────────────────────────────────────────────

def patch_runtimes_config(veecli_path: str, java_major: str):
    """Patch runtimes-config.json so Java entries point to the dirs we actually installed.

    veecli ships with paths like openjdk-17.0.18_linux-amd64 but we install
    openjdk-17.0.2_linux-amd64 (different patch). We keep the entry name
    (e.g. java-jdk-17.0.18) so tools-config.json references still resolve —
    we only fix the path.
    """
    veecli_dir = Path(veecli_path).parent
    config_path = veecli_dir / "third_party" / "runtimes-config.json"
    linux_dir = veecli_dir / "third_party" / "linux"

    if not config_path.exists():
        log("warn", f"runtimes-config.json not found at {config_path} — skipping patch")
        return

    # Find which dirs we installed for this major version
    installed = [
        d.name for d in linux_dir.iterdir()
        if d.is_dir() and re.match(rf"openjdk-{java_major}[\._]", d.name)
    ] if linux_dir.exists() else []

    if not installed:
        log("warn", f"No installed JDK found for Java {java_major} in {linux_dir}")
        return

    installed_dir = installed[0]
    log("info", f"Patching runtimes-config.json: Java {java_major} → {installed_dir}")

    with config_path.open() as f:
        cfg = json.load(f)

    patched = 0
    for entry in cfg.get("runtimes", []):
        if entry.get("provider") != "JavaRuntimeProvider":
            continue
        if re.search(rf"openjdk-{java_major}[\._]", entry.get("path", "")):
            entry["path"] = f"third_party/linux/{installed_dir}"
            patched += 1

    with config_path.open("w") as f:
        json.dump(cfg, f, indent=4)

    log("info", f"runtimes-config.json: {patched} Java {java_major} path(s) updated")


def patch_runtimes_config_python(veecli_path: str, python_minor: str):
    """Add a Python entry to runtimes-config.json if the requested version is absent.

    NOTE: Previously disabled due to nil pointer crashes in veecli 0.9.9. The
    root cause was missing venv pipdeptree, not this patch. Now that pipdeptree
    is installed in both the per-version env and the action venv, this is safe.

    veecli's bundled runtimes-config.json only knows about Python versions that were
    available when veecli was built.  Newer versions (e.g. 3.12) cause a nil-pointer
    crash when veecli finds requires-python >=3.12 but has no matching runtime entry.
    We clone the nearest existing Python entry and retarget it to the installed dir.

    python_minor: e.g. "3.12"
    """
    veecli_dir = Path(veecli_path).parent
    config_path = veecli_dir / "third_party" / "runtimes-config.json"

    if not config_path.exists():
        log("warn", f"runtimes-config.json not found at {config_path} — skipping Python patch")
        return

    with config_path.open() as f:
        cfg = json.load(f)

    runtimes = cfg.get("runtimes", [])
    python_entries = [e for e in runtimes if "Python" in e.get("provider", "")]

    if not python_entries:
        log("warn", "No Python entries found in runtimes-config.json — skipping patch")
        return

    # Check whether an entry for this minor version already exists.
    dir_name = f"python{python_minor.replace('.', '')}"  # e.g. python312
    already_present = any(dir_name in e.get("path", "") for e in python_entries)
    if already_present:
        log("info", f"runtimes-config.json already has a Python {python_minor} entry — skipping")
        return

    # Verify we actually installed the runtime before adding the entry.
    installed_bin = THIRD_PARTY / dir_name / "bin" / f"python{python_minor}"
    if not installed_bin.exists():
        log("warn", f"Python {python_minor} binary not found at {installed_bin} — skipping config patch")
        return

    # Clone the highest existing Python entry and retarget it.
    template = sorted(python_entries, key=lambda e: e.get("path", ""), reverse=True)[0]
    new_entry = copy.deepcopy(template)
    # Update any version-specific fields (e.g. "version": "3.11") via regex.
    for key in list(new_entry.keys()):
        val = new_entry[key]
        if isinstance(val, str):
            new_entry[key] = re.sub(r"3\.\d+", python_minor, val)
    # Override path explicitly to the full binary — veecli executes this path
    # directly, so it must point to the binary, not the directory.
    binary_path = f"third_party/linux/{dir_name}/bin/python{python_minor}"
    new_entry["path"] = binary_path
    runtimes.append(new_entry)
    cfg["runtimes"] = runtimes

    with config_path.open("w") as f:
        json.dump(cfg, f, indent=4)

    log("info", f"runtimes-config.json: added Python {python_minor} entry (path: {binary_path})")


# ── veecli helpers ─────────────────────────────────────────────────────────────

def _ensure_executable(veecli: str):
    veecli_path = Path(veecli)
    if not veecli_path.exists():
        sys.exit(f"[error] veecli not found: {veecli}")
    if not os.access(veecli, os.X_OK):
        log("warn", f"{veecli} not executable — chmod +x")
        try:
            veecli_path.chmod(veecli_path.stat().st_mode | 0o111)
        except PermissionError:
            subprocess.run(["sudo", "chmod", "+x", veecli], check=True)


def _run_veecli(cmd: list, veecli_cwd: str) -> str:
    log("info", f"Running: {' '.join(cmd)}")
    log("info", f"Working directory: {veecli_cwd}")
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=veecli_cwd)
    output = result.stdout + result.stderr
    print(output, flush=True)
    log("info", f"veecli exit code: {result.returncode}")
    if result.returncode != 0:
        sys.exit(f"[error] veecli exited with code {result.returncode}")
    return output


def run_veecli_image(
    veecli: str,
    image: str,
    name: str,
    version: str,
    org_name: str,
    output_dir: str,
    metafiles: str,
    image_source_type: str,
) -> str:
    _ensure_executable(veecli)
    cmd = [
        veecli, "collect",
        "--image-source", f"{image_source_type}:{image}",
        "-o", output_dir,
        "--project", name,
        "--version", version,
        "--fast-scan",
    ]
    if org_name:
        cmd.extend(["--org-name", org_name])
    if metafiles:
        cmd.extend(["--metafiles", str(Path(metafiles).resolve())])
    return _run_veecli(cmd, str(Path(veecli).parent))


def write_input_json(
    path: str,
    project: str,
    version: str,
    src_url: str,
    matching_ref: str,
    src_folder: str,
    exclude_test: bool,
    exclude_optional: bool,
):
    data = {
        "project": project,
        "version": version,
        "exclude_test_dependency": exclude_test,
        "exclude_optional_dependency": exclude_optional,
        "use_native_tools": True,
        "inputtype": "github",
        "inputs": [
            {
                "src_info": {
                    "srcurl": src_url,
                    "matchingref": matching_ref,
                    "src_folder": src_folder,
                    "type": "github",
                }
            }
        ],
        "repository_access_configs": [],
        "artifactory_access_configs": [],
    }
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as f:
        json.dump(data, f, indent=2)
    log("info", f"input.json written to {out}")
    log("debug", json.dumps(data, indent=2))


def run_veecli_source(
    veecli: str,
    input_json: str,
    org_name: str,
    output_dir: str,
    fast_scan: bool,
) -> str:
    _ensure_executable(veecli)
    cmd = [
        veecli, "collect",
        "--inputfile", str(Path(input_json).resolve()),
        "-o", output_dir,
        "--verbose",
    ]
    if org_name:
        cmd.extend(["--org-name", org_name])
    if fast_scan:
        cmd.append("--fast-scan")
    return _run_veecli(cmd, str(Path(veecli).parent))


# ── Job ID parsing ─────────────────────────────────────────────────────────────

def parse_job_id(output: str) -> str:
    match = re.search(r"(?:sbom(?:\s+job)?\s+id|SBOM\s+ID)\s*-\s*(\S+)", output, re.IGNORECASE)
    if not match:
        sys.exit("[error] Could not parse SBOM ID from veecli output")
    sbom_id_full = match.group(1).rstrip(",")
    log("info", f"SBOM ID: {sbom_id_full}")
    num_match = re.search(r"-(\d+)$", sbom_id_full)
    if not num_match:
        sys.exit(f"[error] Could not extract job ID from SBOM ID: {sbom_id_full}")
    return num_match.group(1)


# ── SCIM polling ───────────────────────────────────────────────────────────────

TERMINAL_STATES = {"ready for review", "failed"}


def poll_job(
    scim_host: str, token: str, job_id: str, poll_interval: int, max_attempts: int
) -> dict:
    url = f"{scim_host}/scim/api/v1/sbom_jobs/{job_id}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    log("info", f"Polling job {job_id} at {url}")
    log("info", f"Interval: {poll_interval}s, max attempts: {max_attempts}")

    for attempt in range(1, max_attempts + 1):
        try:
            log("info", f"Attempt {attempt}/{max_attempts}...")
            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            log("warn", f"Attempt {attempt}: {e}")
            time.sleep(poll_interval)
            continue

        inner = data.get("result", data)
        status = (
            inner.get("job_status")
            or inner.get("jobStatus")
            or inner.get("status")
            or inner.get("State")
            or inner.get("state")
            or "<unknown>"
        )
        message = inner.get("job_status_message") or inner.get("jobMessage") or ""
        log("info", f"  status: {status!r}  message: {message!r}")

        if status.strip().lower() in TERMINAL_STATES:
            log("info", f"Terminal state: {status!r}")
            return data

        log("info", f"Waiting {poll_interval}s...")
        time.sleep(poll_interval)

    sys.exit(f"[error] Timed out after {max_attempts} attempts for job {job_id}")


# ── Vulnerability summary ──────────────────────────────────────────────────────

def fetch_vulnerability_summary(
    data_host: str, token: str, company_id: str, sbom_id: str
) -> dict:
    url = f"{data_host}/api/v1/lql/components"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "tenant-id": company_id,
    }
    body = {
        "lql": (
            f"vulnerability.severity=all $AND project.id={sbom_id}"
            "|  stats count(vulnerability.severity, vulnerability.exploited)"
        ),
        "limit": 1,
        "company_id": company_id,
        "valueschema": "valueSchema",
        "product_id": 1,
    }
    log("info", f"Fetching vulnerability summary from {url}")
    resp = requests.post(url, headers=headers, json=body, timeout=30)
    resp.raise_for_status()
    return resp.json()


def print_vulnerability_summary(data: dict) -> int:
    stats_key = next((k for k in data if k.startswith("function: stats count")), "")
    stats_dict = data.get(stats_key, {})
    buckets = stats_dict.get("vulnerability_by_severity", {}).get("buckets", [])
    total = data.get("total_hits", 0)

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    for bucket in buckets:
        sev = bucket.get("key", "Unknown")
        if sev in counts:
            counts[sev] = bucket.get("doc_count", 0)

    exploited = 0
    for bucket in stats_dict.get("vulnerability_by_is_exploited", {}).get("buckets", []):
        if str(bucket.get("key_as_string", "")).lower() == "true":
            exploited = bucket.get("doc_count", 0)
            break

    log("info", "=" * 50)
    log("info", "VULNERABILITY SUMMARY")
    log("info", "=" * 50)
    log("info", f"  Total:     {total}")
    log("info", f"  Critical:  {counts['Critical']}")
    log("info", f"  High:      {counts['High']}")
    log("info", f"  Medium:    {counts['Medium']}")
    log("info", f"  Low:       {counts['Low']}")
    if counts["Unknown"]:
        log("info", f"  Unknown:   {counts['Unknown']}")
    log("info", f"  Exploited: {exploited}")
    log("info", "=" * 50)
    return exploited


# ── Fix plan ──────────────────────────────────────────────────────────────────

def _post_explain(gpt_host: str, token: str, sbom_id: str, query: str, guid: str = None) -> dict:
    url = f"{gpt_host}/api/v1/explain"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    body = {"query": query, "sbom_id": sbom_id}
    if guid:
        body["guid"] = guid
    resp = requests.post(url, headers=headers, json=body, timeout=120)
    resp.raise_for_status()
    return resp.json()


def request_gos_plan(gpt_host: str, token: str, sbom_id: str):
    log("info", f"Requesting gos plan from {gpt_host}/api/v1/explain")
    data = _post_explain(gpt_host, token, sbom_id, "Recommend a gos plan")
    guid = data.get("guid")
    log("info", f"Gos plan submitted — guid: {guid}, message: {data.get('message', '')!r}")
    return guid, data


def request_fix_plan(gpt_host: str, token: str, sbom_id: str):
    log("info", f"Requesting fix plan from {gpt_host}/api/v1/explain")
    data = _post_explain(gpt_host, token, sbom_id, "Recommend a fix plan")
    guid = data.get("guid")
    log("info", f"Fix plan submitted — guid: {guid}, message: {data.get('message', '')!r}")
    return guid, data


def poll_fix_plan(
    gpt_host: str, token: str, sbom_id: str, guid: str,
    poll_interval: int = 20, max_attempts: int = 40,
) -> dict | None:
    """Poll until fix plan overall_status == 'available'.

    Backend has two behaviours:
    1. Plan ready   — blocks on guid, returns guid=null + overall_status='available'.
    2. Plan pending — returns immediately with guid=null + overall_status != 'available'.
       We then send a fresh request (no guid) to get a new guid and retry.
    """
    current_guid = guid
    log("info", f"Polling fix plan (initial guid: {current_guid})")

    for attempt in range(1, max_attempts + 1):
        log("info", f"Fix plan poll {attempt}/{max_attempts}...")
        time.sleep(poll_interval)

        try:
            data = _post_explain(gpt_host, token, sbom_id, "Recommend a fix plan", guid=current_guid)
        except requests.RequestException as e:
            log("warn", f"Fix plan poll {attempt}: {e}")
            continue

        resp_guid = data.get("guid")
        overall_status = data.get("meta_data", {}).get("overall_status", "")
        log("info", f"  guid: {resp_guid}, overall_status: {overall_status!r}, message: {data.get('message', '')!r}")

        if resp_guid is None and overall_status == "available":
            log("info", "Fix plan ready.")
            print(json.dumps(data, indent=2), flush=True)
            return data

        if resp_guid is None:
            log("info", "  guid expired (plan not ready), sending fresh request next poll")
            current_guid = None
        else:
            current_guid = resp_guid

    log("warn", f"Fix plan timed out after {max_attempts} attempts")
    return None


def download_artifacts(data: dict, output_dir: str = "."):
    artifacts = data.get("meta_data", {}).get("artifacts", [])
    if not artifacts:
        log("warn", "No artifacts in fix plan response")
        return

    log("info", f"Found {len(artifacts)} artifact(s) to download")
    for url in artifacts:
        filename = unquote(url.split("?")[0].split("/")[-1])
        dest = Path(output_dir) / filename
        log("info", f"Downloading artifact: {filename}")
        try:
            resp = requests.get(url, timeout=60)
            resp.raise_for_status()
            dest.write_bytes(resp.content)
            log("info", f"Artifact saved to {dest}")
            if filename.endswith(".tar.gz") or filename.endswith(".tgz"):
                import tarfile
                with tarfile.open(dest) as tf:
                    members = tf.getmembers()
                    tf.extractall(path=output_dir)
                log("info", f"Extracted {filename} to {output_dir}")
                for member in members:
                    extracted = Path(output_dir) / member.name
                    if extracted.is_file():
                        log("info", f"--- {member.name} ---")
                        print(extracted.read_text(errors="replace"), flush=True)
                        log("info", f"--- end of {member.name} ---")
            else:
                log("info", f"--- {filename} ---")
                print(resp.text, flush=True)
                log("info", f"--- end of {filename} ---")
        except requests.RequestException as e:
            log("warn", f"Failed to download {filename}: {e}")


def print_fix_plan(data: dict):
    meta = data.get("meta_data", {})
    plan_details = meta.get("plan_details", [])
    overall_status = meta.get("overall_status", "unknown")

    if not plan_details:
        log("info", "No fix plan details available")
        return

    total_critical = total_high = total_medium = total_low = 0
    all_cves: set = set()
    curated_count = premium_count = 0

    for plan in plan_details:
        vc = plan.get("vuln_fix_count", {})
        total_critical += vc.get("critical", 0)
        total_high     += vc.get("high", 0)
        total_medium   += vc.get("medium", 0)
        total_low      += vc.get("low", 0)
        all_cves.update(plan.get("vuln_fixed", []))
        ptype = plan.get("type", "")
        if ptype == "curated":
            curated_count += 1
        elif ptype == "premium":
            premium_count += 1

    log("info", "=" * 70)
    log("info", "FIX PLAN RECOMMENDATIONS")
    log("info", f"Overall status: {overall_status}")
    log("info", f"Components with available fixes: {len(plan_details)}")
    log("info", "=" * 70)
    log("info", "AGGREGATE SUMMARY:")
    log("info", f"  Total unique CVEs fixed: {len(all_cves)}")
    log("info", f"  Critical: {total_critical}  High: {total_high}  Medium: {total_medium}  Low: {total_low}")
    log("info", f"  Curated patches (low effort): {curated_count}")
    log("info", f"  Premium patches (high effort): {premium_count}")
    log("info", "-" * 70)

    for plan in plan_details:
        current_purl = plan.get("current_purl", "")
        pkg_match = re.search(r"/([^@]+)@", current_purl)
        pkg_name  = pkg_match.group(1) if pkg_match else current_purl[:40]
        cur_ver_match = re.search(r"@([^?]+)", current_purl)
        cur_ver = cur_ver_match.group(1) if cur_ver_match else "?"
        fix_ver  = plan.get("fix_version", "?")
        vc = plan.get("vuln_fix_count", {})
        log("info", f"  {pkg_name}")
        log("info", f"    Current: {cur_ver}  →  Fix: {fix_ver}")
        log("info", f"    Type: {plan.get('type','?')}  Effort: {plan.get('efforts','?')}  Compatible: {plan.get('is_compatible','?')}")
        log("info", f"    Vulns fixed — C:{vc.get('critical',0)} H:{vc.get('high',0)} M:{vc.get('medium',0)} L:{vc.get('low',0)}")
        log("info", f"    CVEs: {', '.join(plan.get('vuln_fixed', []))}")
        log("info", "")

    log("info", "=" * 70)


def _run_fix_plan(gpt_host: str, token: str, sbom_id: str, output_dir: str,
                  poll_interval: int, max_attempts: int):
    """Orchestrate gos plan → fix plan request → poll → print → download."""
    try:
        request_gos_plan(gpt_host, token, sbom_id)
        guid, initial_data = request_fix_plan(gpt_host, token, sbom_id)
        if guid:
            fix_data = poll_fix_plan(
                gpt_host, token, sbom_id, guid,
                poll_interval=poll_interval,
                max_attempts=max_attempts,
            )
            if not fix_data:
                sys.exit("[error] Fix plan not available after maximum polling attempts")
        else:
            fix_data = initial_data

        overall_status = fix_data.get("meta_data", {}).get("overall_status", "")
        plan_details   = fix_data.get("meta_data", {}).get("plan_details", [])

        if overall_status == "available" and not plan_details:
            log("info", fix_data.get("answer") or "No fixes available.")
            log("info", "No patch artifacts to download")
        else:
            print_fix_plan(fix_data)
            download_artifacts(fix_data, output_dir=output_dir)
    except Exception as e:
        log("warn", f"Failed to fetch fix plan: {e}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Lineaje scan orchestrator — container images and source code"
    )

    # scan identity (both modes)
    parser.add_argument("--name",     required=True, help="Lineaje project name")
    parser.add_argument("--version",  required=True, help="Lineaje project version")
    parser.add_argument("--org-name", default="", help="Lineaje organization name (auto-derived from token if omitted)")

    # image scan args
    parser.add_argument("--image",             default="", help="Container image reference (activates image scan mode)")
    parser.add_argument("--metafiles",         default="Dockerfile", help="Path to Dockerfile or metafiles (image scan)")
    parser.add_argument("--image-source-type", default="registry", choices=["registry", "daemon"],
                        help="Image source type for veecli (default: registry)")

    # source scan args
    parser.add_argument("--src-folder",   default="", help="Local path to checked-out source (activates source scan mode)")
    parser.add_argument("--language", default="", choices=["", "java", "python", "node", "dotnet"],
                        help="Language runtime to install before scanning (source scan only)")
    parser.add_argument("--language-version", default="",
                        help=(
                            "Required when --language is set. "
                            "java: Java major version (e.g. '17', '11') — "
                            "all Maven and Gradle versions are always installed. "
                            "python: Python minor (e.g. '3.11', '3.14'). "
                            "node: Node major or full (e.g. '18', '16.20.2')."
                        ))
    parser.add_argument("--src-url",      default="", help="GitHub repository URL (source scan)")
    parser.add_argument("--matching-ref", default="", help="Branch / tag / commit (source scan)")
    parser.add_argument("--fast-scan",    action="store_true", default=True, help="Pass --fast-scan to veecli (source scan)")
    parser.add_argument("--no-fast-scan", dest="fast_scan", action="store_false")
    parser.add_argument("--exclude-test-dependency",     default="true", help="Exclude test deps (source scan, true/false)")
    parser.add_argument("--exclude-optional-dependency", default="true", help="Exclude optional deps (source scan, true/false)")
    parser.add_argument("--input-json", default="/tmp/lineaje-input.json", help="Where to write input.json (source scan)")

    # auth / config (both modes)
    parser.add_argument("--refresh-token", required=True, help="Lineaje refresh token")
    parser.add_argument("--config-orig",   required=True, help="Path to config-orig.json from veecli tarball")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="Destination for generated config.json")

    # paths (both modes)
    parser.add_argument("--veecli",     default="veecli",                   help="Path to veecli binary")
    parser.add_argument("--output-dir", default="/tmp/lineaje-scan-output", help="Output directory for veecli")

    # polling (both modes)
    parser.add_argument("--poll-interval", type=int, default=30, help="Seconds between status polls")
    parser.add_argument("--max-attempts",  type=int, default=30, help="Max polling attempts")

    # optional overrides (both modes)
    parser.add_argument("--data-host",  default="", help="Data service URL (default: from config)")
    parser.add_argument("--company-id", default=None, help="Company ID (auto-detected from token)")

    # fix plan (both modes)
    parser.add_argument("--gpt-host", default="", help="Lineaje GPT service base URL (default: GPTServiceHost from config, falls back to built-in prod URL)")
    parser.add_argument("--fix-plan-poll-interval", type=int, default=20, help="Seconds between fix plan polls (default: 20)")
    parser.add_argument("--fix-plan-max-attempts",  type=int, default=50, help="Max fix plan poll attempts (default: 50, ~17 min)")
    parser.add_argument("--skip-fix-plan", action="store_true", default=False, help="Skip fix plan after scan")

    args = parser.parse_args()

    # ── Determine scan mode ────────────────────────────────────────────────────
    if args.image and args.src_folder:
        sys.exit("[error] Provide either --image or --src-folder, not both")
    if not args.image and not args.src_folder:
        sys.exit("[error] Provide either --image (image scan) or --src-folder (source scan)")

    scan_mode = "image" if args.image else "source"

    if scan_mode == "source":
        if not args.src_url:
            sys.exit("[error] --src-url is required for source scan")
        if not args.matching_ref:
            sys.exit("[error] --matching-ref is required for source scan")

    log("info", f"Scan mode: {scan_mode}")
    log("info", f"Project:  {args.name} v{args.version} (org: {args.org_name})")
    if scan_mode == "image":
        log("info", f"Image:    {args.image} (source: {args.image_source_type})")
    else:
        log("info", f"Source:   {args.src_url} @ {args.matching_ref}")
        log("info", f"Folder:   {args.src_folder}")
        if args.language:
            log("info", f"Language: {args.language} {args.language_version}")
    log("info", f"Veecli:   {args.veecli}")

    # ── 0. Language runtime setup (source scan only) ───────────────────────────
    if scan_mode == "source" and args.language:
        if not args.language_version:
            _AVAILABLE = {
                "java":   "Java major version: 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25",
                "python": "Python minor: 3.6, 3.7, 3.8, 3.9, 3.10, 3.11, 3.12, 3.13, 3.14",
                "node":   f"Node major or full: {', '.join(NODE_VERSIONS)}",
                "dotnet": ".NET channel: 6.0, 7.0, 8.0, 9.0",
            }
            sys.exit(
                f"[error] --language-version is required when --language is set.\n"
                f"  Available for {args.language}: {_AVAILABLE[args.language]}"
            )

        if args.language == "java":
            setup_java_runtime(args.language_version)
            patch_runtimes_config(args.veecli, args.language_version)
        elif args.language == "python":
            setup_python_runtime(args.language_version)
            patch_runtimes_config_python(args.veecli, args.language_version)
        elif args.language == "node":
            setup_node_runtime(args.language_version)
        elif args.language == "dotnet":
            log("info", f".NET {args.language_version} — runtime installed by action setup step")

    # ── 1. Build config.json ───────────────────────────────────────────────────
    veecli_dir = Path(args.veecli).parent
    if Path(args.config).exists():
        log("info", "Reusing existing config.json (token already exchanged this job)")
    else:
        build_config(args.config_orig, args.refresh_token, args.config)
        shutil.copy2(args.config, veecli_dir / "config.json")
        log("info", f"Copied config.json to {veecli_dir}/config.json")

    # ── 2. Run veecli collect ──────────────────────────────────────────────────
    if scan_mode == "image":
        output = run_veecli_image(
            args.veecli, args.image, args.name, args.version,
            args.org_name, args.output_dir, args.metafiles, args.image_source_type,
        )
    else:
        exclude_test     = args.exclude_test_dependency.lower()     not in ("false", "0", "no")
        exclude_optional = args.exclude_optional_dependency.lower() not in ("false", "0", "no")
        write_input_json(
            args.input_json,
            project=args.name,
            version=args.version,
            src_url=args.src_url,
            matching_ref=args.matching_ref,
            src_folder=str(Path(args.src_folder).resolve()),
            exclude_test=exclude_test,
            exclude_optional=exclude_optional,
        )
        output = run_veecli_source(
            args.veecli, args.input_json, args.org_name, args.output_dir, args.fast_scan,
        )

    job_id = parse_job_id(output)
    log("info", f"Job ID: {job_id}")

    # ── 3. Reload config (veecli may have refreshed the token) ─────────────────
    cfg = load_config(args.config)
    token = get_auth_token(cfg)
    scim_host = get_scim_host(cfg)
    data_host = get_data_host(cfg, args.data_host)

    # ── 4. Poll until terminal ─────────────────────────────────────────────────
    result = poll_job(scim_host, token, job_id, args.poll_interval, args.max_attempts)

    inner = result.get("result", result)
    status  = inner.get("job_status") or inner.get("jobStatus") or inner.get("status") or ""
    message = inner.get("job_status_message") or inner.get("jobMessage") or ""
    log("info", f"Final status: {status!r}")
    print(json.dumps(result, indent=2), flush=True)

    if status.strip().lower() == "failed":
        sys.exit(f"[error] Scan failed — {message}")
    if status.strip().lower() != "ready for review":
        sys.exit(f"[error] Unexpected terminal status: {status!r}")

    log("info", "Scan completed — Ready for review")

    sbom_id    = inner.get("sbom_id", "")
    company_id = args.company_id or get_company_id_from_token(token)

    # ── 5. Vulnerability summary ───────────────────────────────────────────────
    if sbom_id and company_id:
        try:
            vuln_data = None
            for attempt in range(1, 6):
                log("info", f"Fetching vulnerability summary (attempt {attempt}/5)...")
                vuln_data = fetch_vulnerability_summary(data_host, token, company_id, sbom_id)
                if vuln_data.get("total_hits", 0) > 0:
                    break
                if attempt < 5:
                    log("info", "No vulnerabilities indexed yet — retrying in 15s...")
                    time.sleep(15)
            if vuln_data:
                exploited_count = print_vulnerability_summary(vuln_data)
        except Exception as e:
            log("warn", f"Failed to fetch vulnerability summary: {e}")
    else:
        log("warn", f"Skipping vulnerability summary (sbom_id={sbom_id!r}, company_id={company_id!r})")

    # ── 6. Fix plan ────────────────────────────────────────────────────────────
    gpt_host = get_gpt_host(cfg, args.gpt_host)
    if not sbom_id:
        log("warn", "Skipping fix plan (no sbom_id)")
    elif args.skip_fix_plan:
        log("info", "Skipping fix plan (--skip-fix-plan)")
    elif not gpt_host:
        log("info", "Skipping fix plan (--gpt-host not provided)")
    else:
        log("info", f"Requesting fix plan (scan mode: {scan_mode})...")
        _run_fix_plan(
            gpt_host, token, sbom_id, args.output_dir,
            poll_interval=args.fix_plan_poll_interval,
            max_attempts=args.fix_plan_max_attempts,
        )


if __name__ == "__main__":
    main()
