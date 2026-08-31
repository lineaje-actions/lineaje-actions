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
from urllib.parse import quote, unquote

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

MAVEN_VERSION = "3.8.9"
MAVEN_URL = f"https://archive.apache.org/dist/maven/maven-3/{MAVEN_VERSION}/binaries/apache-maven-{MAVEN_VERSION}-bin.tar.gz"
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

# ── Go runtime data ────────────────────────────────────────────────────────────

# Maps Go minor version → latest patch release (e.g. "1.21" → "1.21.13")
GO_VERSIONS = {
    "1.18": "1.18.10",
    "1.19": "1.19.13",
    "1.20": "1.20.14",
    "1.21": "1.21.13",
    "1.22": "1.22.12",
    "1.23": "1.23.12",
    "1.24": "1.24.13",
    "1.25": "1.25.11",
    "1.26": "1.26.4",
}

CYCLONEDX_GOMOD_VERSION = "1.10.0-3-lineaje"
CYCLONEDX_GOMOD_REPO   = "lineaje-labs/cyclonedx-gomod"


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

    for version in versions_to_install:
        bin_dir = str(THIRD_PARTY / f"node-{version}" / "bin")
        if (Path(bin_dir) / "npm").exists():
            path = os.environ.get("PATH", "")
            if bin_dir not in path.split(os.pathsep):
                os.environ["PATH"] = bin_dir + os.pathsep + path
                log("info", f"Added {bin_dir} to PATH")

    log("info", "Node.js runtime setup complete")


def setup_go_runtime(version: str):
    """Install a specific Go version and cyclonedx-gomod into /opt/veecli/third_party/linux/.

    version: Go minor version (e.g. "1.21"). Resolves to the latest known patch release.
    """
    if version not in GO_VERSIONS:
        available = sorted(GO_VERSIONS.keys())
        sys.exit(
            f"[error] Go {version!r} not available. "
            f"Available: {', '.join(available)}"
        )

    full_version = GO_VERSIONS[version]

    machine = platform.machine()
    if machine == "x86_64":
        arch = "amd64"
    elif machine == "aarch64":
        arch = "arm64"
    else:
        sys.exit(f"[error] Unsupported architecture for Go: {machine}")

    log("info", f"Setting up Go {version} (full: {full_version}, arch: {arch})")

    with tempfile.TemporaryDirectory(prefix="lineaje-go-setup-") as tmp:
        tmp_path = Path(tmp)

        # ── Install Go ─────────────────────────────────────────────────────────
        go_dest = THIRD_PARTY / f"go-{version}"
        go_bin = go_dest / "bin" / "go"

        if go_bin.exists():
            log("info", f"Skipping Go {full_version} — already installed")
        else:
            go_dest.mkdir(parents=True, exist_ok=True)
            filename = f"go{full_version}.linux-{arch}.tar.gz"
            url = f"https://go.dev/dl/{filename}"
            archive = tmp_path / filename
            _download(url, archive)
            _extract_tar_strip1(archive, go_dest)
            archive.unlink(missing_ok=True)
            if go_bin.exists():
                log("info", f"Installed Go {full_version}: {go_bin}")
            else:
                log("warn", f"go binary not found after extracting Go {full_version}")

        # ── Install cyclonedx-gomod ────────────────────────────────────────────
        cdx_dest = THIRD_PARTY / "cyclonedx-gomod"
        cdx_bin = cdx_dest / "cyclonedx-gomod"

        if cdx_bin.exists():
            log("info", "Skipping cyclonedx-gomod — already installed")
        else:
            cdx_dest.mkdir(parents=True, exist_ok=True)
            cdx_filename = f"cyclonedx-gomod_{CYCLONEDX_GOMOD_VERSION}_linux_{arch}.tar.gz"
            cdx_url = (
                f"https://github.com/{CYCLONEDX_GOMOD_REPO}/releases/download"
                f"/v{CYCLONEDX_GOMOD_VERSION}/{cdx_filename}"
            )
            cdx_archive = tmp_path / cdx_filename
            _download(cdx_url, cdx_archive)
            _kwargs = {"filter": "data"} if sys.version_info >= (3, 12) else {}
            with tarfile.open(cdx_archive, "r:*") as tf:
                tf.extractall(cdx_dest, **_kwargs)
            cdx_archive.unlink(missing_ok=True)
            if cdx_bin.exists():
                cdx_bin.chmod(cdx_bin.stat().st_mode | 0o111)
                log("info", f"Installed cyclonedx-gomod {CYCLONEDX_GOMOD_VERSION}: {cdx_bin}")
            else:
                log("warn", "cyclonedx-gomod binary not found after extraction")

    # ── Symlink cyclonedx-gomod into the Go bin dir ────────────────────────────
    # veecli's bundled runtimes-config.json only has a cyclonedx-gomod entry for
    # Go 1.18. For any other version it falls back to searching the Go runtime
    # bin directory. Symlinking there ensures the fallback always succeeds.
    cdx_symlink = go_dest / "bin" / "cyclonedx-gomod"
    if cdx_bin.exists() and go_bin.exists() and not cdx_symlink.exists():
        cdx_symlink.symlink_to(cdx_bin)
        log("info", f"Symlinked cyclonedx-gomod into {go_dest}/bin/")

    # ── Set GOROOT and update PATH ─────────────────────────────────────────────
    goroot = str(go_dest)
    go_bin_dir = str(go_dest / "bin")
    os.environ["GOROOT"] = goroot
    path = os.environ.get("PATH", "")
    if go_bin_dir not in path.split(os.pathsep):
        os.environ["PATH"] = go_bin_dir + os.pathsep + path
    log("info", f"GOROOT={goroot}, added {go_bin_dir} to PATH")

    # ── Persist Go env settings via go env -w ─────────────────────────────────
    # veecli resets the subprocess environment to only PATH + GOROOT, so
    # os.environ changes don't reach the go binary called by cyclonedx-gomod.
    # Writing to ~/.config/go/env (via `go env -w`) is a file-based config that
    # ALL go binaries on this runner read, including the system /usr/bin/go.
    # This fixes "GOPROXY list contains no entries" and "missing GOSUMDB" errors
    # that occur when Ubuntu's golang-go package ships with empty defaults.
    if go_bin.exists():
        result = subprocess.run(
            [str(go_bin), "env", "-w",
             "GOPROXY=https://proxy.golang.org,direct",
             "GONOSUMDB=*"],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            log("info", "Configured GOPROXY and GONOSUMDB in Go env file (~/.config/go/env)")
        else:
            log("warn", f"go env -w failed (non-fatal): {result.stderr.strip()}")
    else:
        log("warn", "Skipping go env -w — go binary not available after extraction")

    log("info", "Go runtime setup complete")


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


def build_config(config_orig_path: str, refresh_token: str, output_path: str, host_overrides: dict = None):
    """host_overrides maps config.json host keys (e.g. "SCIMHost") to override
    values. veecli itself reads config.json directly for several of these
    (SCIMHost, SCMHost, NotificationServiceHost, GraphQLServiceHost) — so
    overrides must be baked into config.json here, not applied only at the
    point our own script calls out to a host."""
    orig = Path(config_orig_path)
    if not orig.exists():
        sys.exit(f"[error] config-orig.json not found: {orig}")
    with orig.open() as f:
        config_orig = json.load(f)

    for key, value in (host_overrides or {}).items():
        if value:
            config_orig[key] = value.rstrip("/")

    auth_service = config_orig.get("LineajeAuthService", "").rstrip("/")
    if not auth_service:
        sys.exit("[error] LineajeAuthService not found in config-orig.json (and --auth-service not supplied)")

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
    host = (cfg.get("GPTServiceHost") or "").rstrip("/")
    if host:
        return host
    # DEFAULT_GPT_HOST is a production URL. Falling back to it silently would
    # send a non-prod scan's fix plan to prod, so say so loudly.
    log("warn", f"GPTServiceHost is absent from config.json and --gpt-host was not supplied — "
                f"falling back to the built-in production URL {DEFAULT_GPT_HOST}. "
                f"If this scan targets a non-prod cell, set the gpt_host input explicitly.")
    return DEFAULT_GPT_HOST


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


def patch_tools_config_maven(veecli_path: str):
    """Patch tools-config.json so the Maven entry points to the version we installed.

    veecli ships tools-config-orig.json (copied to tools-config.json by pre.sh)
    with a single MvnProvider entry hardcoded to maven-3.8.9, but we install
    MAVEN_VERSION into maven-{MAVEN_VERSION}. Without this patch veecli can't
    find our Maven, logs "maven tool not found", and silently falls back to
    whatever mvn is on the runner's PATH.
    """
    veecli_dir = Path(veecli_path).parent
    config_path = veecli_dir / "third_party" / "tools-config.json"

    if not config_path.exists():
        log("warn", f"tools-config.json not found at {config_path} — skipping Maven patch")
        return

    with config_path.open() as f:
        cfg = json.load(f)

    patched = 0
    for entry in cfg.get("tools", []):
        if entry.get("provider") != "MvnProvider":
            continue
        entry["version"] = MAVEN_VERSION
        entry["path"] = f"third_party/linux/{MAVEN_DIR}/bin/mvn"
        patched += 1

    with config_path.open("w") as f:
        json.dump(cfg, f, indent=4)

    log("info", f"tools-config.json: {patched} Maven entr{'y' if patched == 1 else 'ies'} updated to {MAVEN_VERSION}")


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


def patch_runtimes_config_go(veecli_path: str, go_minor: str):
    """Add a Go entry to runtimes-config.json if the requested minor version is absent.

    veecli's bundled runtimes-config.json only contains entries for the Go versions
    that were available when the image was built (1.18, 1.21, 1.23, 1.25).
    Requesting any other version (1.19, 1.20, 1.22, 1.24, 1.26) without this patch
    causes veecli to silently skip the Go runtime.

    go_minor: e.g. "1.22"
    """
    veecli_dir = Path(veecli_path).parent
    config_path = veecli_dir / "third_party" / "runtimes-config.json"

    if not config_path.exists():
        log("warn", f"runtimes-config.json not found at {config_path} — skipping Go patch")
        return

    with config_path.open() as f:
        cfg = json.load(f)

    runtimes = cfg.get("runtimes", [])
    go_entries = [e for e in runtimes if "Go" in e.get("provider", "")]

    if not go_entries:
        log("warn", "No Go entries found in runtimes-config.json — skipping patch")
        return

    dir_name = f"go-{go_minor}"
    already_present = any(dir_name in e.get("path", "") for e in go_entries)
    if already_present:
        log("info", f"runtimes-config.json already has a Go {go_minor} entry — skipping")
        return

    installed_bin = THIRD_PARTY / dir_name / "bin" / "go"
    if not installed_bin.exists():
        log("warn", f"Go {go_minor} binary not found at {installed_bin} — skipping config patch")
        return

    template = sorted(go_entries, key=lambda e: e.get("path", ""), reverse=True)[0]
    new_entry = copy.deepcopy(template)
    # Only update the known version-bearing keys — do not regex-replace all fields
    # blindly, as a pattern like r"1\.\d+" would corrupt full patch versions
    # (e.g. "1.18.10" → "1.22.10") and any unrelated "1.XX" substrings.
    for key in ("version", "minVersion", "maxVersion"):
        if key in new_entry and isinstance(new_entry[key], str):
            new_entry[key] = re.sub(r"1\.\d+", go_minor, new_entry[key])
    binary_path = f"third_party/linux/{dir_name}/bin/go"
    new_entry["path"] = binary_path
    runtimes.append(new_entry)
    cfg["runtimes"] = runtimes

    with config_path.open("w") as f:
        json.dump(cfg, f, indent=4)

    log("info", f"runtimes-config.json: added Go {go_minor} entry (path: {binary_path})")


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


def _gos_premium_env(token: str, gos_mode: str) -> dict:
    return {
        "GOS_PREMIUM_REGISTRY_TOKEN": token,
        "ARTIFACTORY_NPM_TOKEN": token,
        "GOS_PREMIUM_NPM_REGISTRY": f"https://{gos_mode}.fortknox.v2.prod.veedna.com/artifactory/api/npm/gos-all-proxy-npm",
        "GOS_PREMIUM_REGISTRY_USERNAME": "lineaje_customer@lineaje.com",
    }


def _run_veecli(cmd: list, veecli_cwd: str, token: str, gos_mode: str, fatal: bool = True) -> str:
    """fatal=False raises instead of exiting, so a caller inside the best-effort
    fix plan path can log a warning and leave the scan result standing.

    Streams veecli's output line-by-line as it happens rather than buffering the
    whole run and printing it in one burst at the end — `veecli fix --poll-tasks`
    in particular can run for minutes and log continuously, so buffering meant the
    log went silent for the entire run and then dumped everything at once. stderr
    is merged into the same stream (rather than appended after stdout) so lines
    print in the order veecli actually emitted them.
    """
    log("info", f"Running: {' '.join(cmd)}")
    log("info", f"Working directory: {veecli_cwd}")
    env = {**os.environ, **_gos_premium_env(token, gos_mode)}
    proc = subprocess.Popen(
        cmd, cwd=veecli_cwd, env=env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1,
    )
    lines = []
    for line in proc.stdout:
        print(line, end="", flush=True)
        lines.append(line)
    proc.wait()
    output = "".join(lines)
    log("info", f"veecli exit code: {proc.returncode}")
    if proc.returncode != 0:
        if fatal:
            sys.exit(f"[error] veecli exited with code {proc.returncode}")
        raise RuntimeError(f"veecli exited with code {proc.returncode}")
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
    token: str,
    gos_mode: str,
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
    return _run_veecli(cmd, str(Path(veecli).parent), token, gos_mode)


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
    token: str,
    gos_mode: str,
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
    return _run_veecli(cmd, str(Path(veecli).parent), token, gos_mode)


def run_veecli_fix(
    veecli: str,
    sbom_id: str,
    local_repo_dir: str,
    output_fix_dir: str,
    token: str,
    gos_mode: str,
) -> str:
    """Download the patched manifests for a fix plan that has already been applied.

    --poll-tasks blocks until the patch tasks queued by apply_fix_left_plan finish,
    then writes the patched manifests into --output-fix-dir, preserving the repo's
    directory layout. Runs non-fatally: a failure here leaves the scan result intact
    and surfaces as fix_artifact_uploaded=false.
    """
    _ensure_executable(veecli)
    Path(output_fix_dir).mkdir(parents=True, exist_ok=True)
    cmd = [
        veecli, "fix",
        "--poll-tasks",
        "--local-repo-dir",  str(Path(local_repo_dir).resolve()),
        "--output-fix-dir",  str(Path(output_fix_dir).resolve()),
        "--sbom-id",         str(sbom_id),
    ]
    return _run_veecli(cmd, str(Path(veecli).parent), token, gos_mode, fatal=False)


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

def _post_explain(gpt_host: str, token: str, sbom_id: str, query: str, guid: str = None,
                  metadata: dict = None) -> dict:
    url = f"{gpt_host}/api/v1/explain"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    body = {"query": query, "sbom_id": sbom_id}
    if guid:
        body["guid"] = guid
    if metadata is not None:
        body["metadata"] = metadata
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


APPLY_FIX_QUERY = "Apply fix left plan without pr"

# The apply request is done once the service has queued its agent tasks. It
# signals that both structurally (task_ids populated) and in prose; task_ids is
# the primary check since the message wording is the more likely thing to drift.
APPLY_FIX_READY_MESSAGE = "Created tasks for AI Agents"

# Terminal-with-no-tasks is an explicit allowlist, NOT "anything that is not a
# known pending message". The service has at least three pending wordings
# ("Request is being processed", "Request is still processing. Please try again
# later.", and the ready message which also contains the first) — inferring
# completion from the absence of one of them made the poll give up on the first
# tick against a wording we had not seen. Unknown wording keeps polling instead,
# where the worst case is waiting out max_attempts rather than silently
# reporting that nothing matched.
APPLY_FIX_DONE_MESSAGES = ("Completed processing",)


def _raise_on_explain_error(data: dict, what: str):
    if data.get("error"):
        raise RuntimeError(f"{what} failed: {data.get('message', '')}")


def apply_fix_left_plan(gpt_host: str, token: str, sbom_id: str, plan_details: list,
                        poll_interval: int = 20, max_attempts: int = 60) -> dict:
    """Submit a fix plan's components to the GPT service and wait for it to queue tasks.

    The service checks each component's suggested_purl against the GOS artifactory
    and queues the patch tasks that `veecli fix --poll-tasks` later waits on. The
    plan_details entries are passed through verbatim as metadata.components —
    what the fix plan returns is already the shape the apply call expects, so no
    client-side filtering happens here and this action never talks to the
    artifactory directly.

    The call is asynchronous. The first POST (no guid) returns a guid with
    "Request is being processed" and an empty task_ids; re-POSTing the same body
    plus that guid polls it, until task_ids is populated and the message becomes
    "Created tasks for AI Agents. Request is being processed". Returning before
    that point would leave `veecli fix --poll-tasks` with nothing to wait on.
    """
    metadata = {"components": plan_details}
    log("info", f"Applying fix plan for {len(plan_details)} component(s) at {gpt_host}/api/v1/explain")

    data = _post_explain(gpt_host, token, sbom_id, APPLY_FIX_QUERY, metadata=metadata)
    _raise_on_explain_error(data, "Apply fix plan")
    guid = data.get("guid")
    log("info", f"Apply fix plan submitted — guid: {guid}, message: {data.get('message', '')!r}")

    for attempt in range(max_attempts + 1):
        task_ids = data.get("task_ids") or []
        message  = data.get("message", "") or ""
        if task_ids or APPLY_FIX_READY_MESSAGE in message:
            log("info", f"Apply fix plan ready — {len(task_ids)} task(s) queued: {task_ids}")
            return data

        # Finished, but nothing queued. Expected when the GOS artifactory has no
        # rebuilt package for any suggested_purl — there is genuinely nothing to
        # patch, which is a result, not a failure. Without this the poll would
        # run to its full timeout and look like a hang.
        if any(done in message for done in APPLY_FIX_DONE_MESSAGES):
            log("info", f"Apply fix plan finished with no tasks queued — "
                        f"message: {message!r}. Nothing in the GOS artifactory matched "
                        f"the suggested fixes.")
            return data

        if attempt == max_attempts:
            break

        time.sleep(poll_interval)
        log("info", f"Apply fix plan poll {attempt + 1}/{max_attempts} (guid: {guid})...")
        try:
            data = _post_explain(gpt_host, token, sbom_id, APPLY_FIX_QUERY,
                                 guid=guid, metadata=metadata)
        except requests.RequestException as e:
            log("warn", f"Apply fix plan poll {attempt + 1}: {e}")
            continue

        _raise_on_explain_error(data, "Apply fix plan")
        # Same guid-expiry quirk as poll_fix_plan: a null guid means the handle is
        # gone, so the next poll re-submits without one and gets a fresh handle.
        guid = data.get("guid")
        log("info", f"  guid: {guid}, message: {data.get('message', '')!r}, "
                    f"task_ids: {data.get('task_ids') or []}")

    raise RuntimeError(
        f"Apply fix plan did not queue tasks after {max_attempts} attempts "
        f"({poll_interval * max_attempts}s) — last message: {data.get('message', '')!r}"
    )


def poll_fix_plan(
    gpt_host: str, token: str, sbom_id: str, guid: str,
    poll_interval: int = 20, max_attempts: int = 40,
) -> dict | None:
    """Poll until the response contains a completed fix plan.

    Backend has two behaviours:
    1. Plan ready   — blocks on guid, returns guid=null + overall_status='available'.
       Rebuild plans may instead omit overall_status and return plan_details.
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
        meta_data = data.get("meta_data", {})
        overall_status = meta_data.get("overall_status", "")
        plan_details = meta_data.get("plan_details") or []
        log("info", f"  guid: {resp_guid}, overall_status: {overall_status!r}, message: {data.get('message', '')!r}")

        if resp_guid is None and (overall_status == "available" or plan_details):
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


def _strip_markdown_fence(text: str) -> str:
    """Strip a wrapping ```lang ... ``` fence the GPT service sometimes leaves in generated files."""
    match = re.match(r"^```[^\n]*\r?\n(.*?)\r?\n?```\s*$", text.strip(), re.DOTALL)
    return match.group(1) if match else text


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
                cleaned = _strip_markdown_fence(resp.text)
                if cleaned != resp.text:
                    log("info", f"Stripped markdown code fence from {filename}")
                    dest.write_text(cleaned)
                log("info", f"--- {filename} ---")
                print(cleaned, flush=True)
                log("info", f"--- end of {filename} ---")
        except requests.RequestException as e:
            log("warn", f"Failed to download {filename}: {e}")


def write_raw_fix_plan(data: dict, output_dir: str = ".") -> Path:
    """Persist the unmodified fix-plan response, for fix_plan and fix_plan_gos_compat runs alike."""
    destination = Path(output_dir) / "raw-fix-plan.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(data, indent=2) + "\n")
    log("info", f"Raw fix plan saved to {destination}")
    return destination


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
    premium_only = len(plan_details) > 0 and curated_count == 0
    log("info", f"  Premium only: {str(premium_only).lower()}")
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
        suggested = plan.get("suggested_purl", "")
        log("info", f"    Current: {cur_ver}  →  Fix: {fix_ver}")
        if suggested:
            log("info", f"    Suggested purl: {suggested}"
                        f"{'  [GOS rebuild]' if '-lineaje-' in suggested else ''}")
        log("info", f"    Type: {plan.get('type','?')}  Effort: {plan.get('efforts','?')}  Compatible: {plan.get('is_compatible','?')}")
        log("info", f"    Vulns fixed — C:{vc.get('critical',0)} H:{vc.get('high',0)} M:{vc.get('medium',0)} L:{vc.get('low',0)}")
        log("info", f"    CVEs: {', '.join(plan.get('vuln_fixed', []))}")
        log("info", "")

    log("info", "=" * 70)


# ── veecli fix config ─────────────────────────────────────────────────────────

VERIFY_SCRIPT_NAME   = "lineaje-verify.sh"
VERIFY_NPMRC_NAME    = "lineaje-verify.npmrc"
VERIFY_PIP_CONF_NAME = "lineaje-verify-pip.conf"

ACTION_DIR    = Path(__file__).resolve().parent
TEMPLATES_DIR = ACTION_DIR / "templates"


def _render_template(name: str, **subs) -> str:
    """Read templates/<name> and substitute __KEY__ placeholders.

    Raises if any placeholder is left unsubstituted, so a renamed or mistyped key
    fails here rather than producing a config file veecli silently misreads.
    """
    path = TEMPLATES_DIR / name
    if not path.exists():
        raise RuntimeError(f"template missing from the action: {path}")
    text = path.read_text()
    for key, value in subs.items():
        text = text.replace(f"__{key}__", str(value))
    leftover = sorted(set(re.findall(r"__[A-Z0-9_]+__", text)))
    if leftover:
        raise RuntimeError(f"{path} has unsubstituted placeholder(s): {', '.join(leftover)}")
    return text


# lineaje-verify.sh ships next to this file and is copied into the veecli dir,
# where it finds its npmrc, pip config and third_party tree relative to itself.
VERIFY_SCRIPT_SRC = Path(__file__).resolve().parent / VERIFY_SCRIPT_NAME

# Agent-level timeout written into fix.yaml.
VERIFY_TIMEOUT_SECONDS = 1800

def _npmrc_content(token: str, gos_mode: str) -> str:
    """Use public npm by default and token auth for the GOS premium registry.

    ARTIFACTORY_NPM_TOKEN is exported to veecli and inherited by the verify hook;
    npm expands that environment reference from the generated user config.
    """
    gos = _gos_premium_env(token, gos_mode)
    registry = gos["GOS_PREMIUM_NPM_REGISTRY"].rstrip("/") + "/"
    return _render_template(
        "npmrc",
        SCOPED=registry.split("://", 1)[1],
    )


def _normalize_pip_index_urls(value: str) -> str:
    """Percent-encode credentials while preserving each index URL's host and path."""
    normalized = []
    for url in value.split():
        scheme, separator, remainder = url.partition("://")
        userinfo, at, location = remainder.rpartition("@")
        username, colon, password = userinfo.partition(":")
        if not (separator and at and colon):
            normalized.append(url)
            continue
        encoded_user = quote(unquote(username), safe="")
        encoded_password = quote(unquote(password), safe="")
        normalized.append(f"{scheme}://{encoded_user}:{encoded_password}@{location}")
    return " ".join(normalized)


def _node_bin_dir(version: str) -> str:
    matches = [candidate for candidate in NODE_VERSIONS
               if candidate == version or candidate.startswith(version + ".")]
    return str(THIRD_PARTY / f"node-{matches[0]}" / "bin") if matches else ""


def write_fix_config(veecli_path: str, token: str = "", gos_mode: str = "observe",
                     language: str = "", language_version: str = "",
                     connect_to_fortknox: bool = True,
                     timeout_seconds: int = VERIFY_TIMEOUT_SECONDS) -> Path:
    """Write fix.yaml and the verify hook's script and credentials into the veecli dir.

    `veecli fix` reads fix.yaml from its own directory, alongside config.json.

    The verify hook is always configured rather than left out, so the step is
    present and visible in the log. It points at a script this action writes
    rather than a conventional path in the user's repo, because a missing script
    would fail the agent and skip the copy for everyone.

    The hook is blocking: a patched manifest whose pins cannot be installed is
    rejected rather than copied, by exiting non-zero. connect_to_fortknox=False
    relies on that: the verify hook is told (via fix.yaml's --connect-to-fortknox
    arg) to check Node.js manifests against the public npm registry instead of
    Fortknox, so any patch that needed a Lineaje-rebuilt version fails to
    install and is rejected rather than uploaded. No effect on Python, whose
    verification never used Fortknox.
    """
    veecli_dir = Path(veecli_path).parent

    # npmrc and pip.conf carry credentials — keep them off other users' reads.
    npmrc = veecli_dir / VERIFY_NPMRC_NAME
    if connect_to_fortknox and token:
        npmrc.write_text(_npmrc_content(token, gos_mode))
        npmrc.chmod(0o600)
        log("info", f"Wrote {npmrc} (GOS premium npm registry, {gos_mode} mode)")
    elif not connect_to_fortknox:
        log("info", "connect_to_fortknox=false — skipping npmrc; verify hook will check "
                    "Node.js manifests against the public npm registry only")
    else:
        log("warn", "No CLI token available — skipping npmrc; "
                    "npm install in the verify hook will not resolve lineaje-rebuilt versions")

    pip_conf = veecli_dir / VERIFY_PIP_CONF_NAME
    extra_index = os.environ.get("PIP_EXTRA_INDEX_URL", "").strip()
    if extra_index:
        pip_conf.write_text(_render_template(
            "pip.conf", EXTRA_INDEX_URL=_normalize_pip_index_urls(extra_index)
        ))
        pip_conf.chmod(0o600)
        log("info", f"Wrote {pip_conf} (extra-index-url from pip_extra_index_url)")

    if not VERIFY_SCRIPT_SRC.exists():
        raise RuntimeError(f"verify script missing from the action: {VERIFY_SCRIPT_SRC}")
    verify_script = veecli_dir / VERIFY_SCRIPT_NAME
    shutil.copy2(VERIFY_SCRIPT_SRC, verify_script)
    verify_script.chmod(verify_script.stat().st_mode | 0o111)

    content = _render_template(
        "fix.yaml",
        VERIFY_SCRIPT=verify_script,
        LANGUAGE=language,
        NODE_BIN_DIR=_node_bin_dir(language_version) if language == "node" else "",
        CONNECT_TO_FORTKNOX=str(connect_to_fortknox).lower(),
        TIMEOUT=timeout_seconds,
    )

    # Both spellings in both directories. The .yml spelling is the one veecli is
    # known to read; .yaml is kept because that is what this action originally
    # wrote. Both directories for the same reason config.json uses both:
    # DEFAULT_CONFIG puts it under ~/veecli/ and main() also copies it next to
    # the binary, so veecli's lookup is not purely relative to its own directory.
    fix_yaml = veecli_dir / "fix.yml"
    written = []
    for directory in (veecli_dir, Path(DEFAULT_CONFIG).parent):
        for name in ("fix.yml", "fix.yaml"):
            target = directory / name
            if any(target.resolve() == w.resolve() for w in written):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                log("warn", f"Overwriting existing {target}")
            target.write_text(content)
            written.append(target)
    log("info", f"Wrote fix config to: {', '.join(str(w) for w in written)}")

    log("info", f"fix.yaml verify hook: {verify_script} (agent timeout {timeout_seconds}s)")
    # Echo the rendered file — it carries no secrets and veecli silently ignoring
    # it is otherwise indistinguishable from it never being written.
    log("info", "--- fix config ---")
    print(content, flush=True)
    log("info", "--- end of fix config ---")
    return fix_yaml


def _print_fix_dir(output_fix_dir: str):
    """Log the paths of patched manifests without exposing their contents."""
    fix_dir = Path(output_fix_dir)
    if not fix_dir.is_dir():
        log("warn", f"Fix output directory not found: {fix_dir}")
        return

    files = sorted(p for p in fix_dir.rglob("*") if p.is_file())
    if not files:
        log("warn", f"No patched manifests written to {fix_dir}")
        return

    log("info", f"veecli fix wrote {len(files)} file(s) to {fix_dir}")
    for path in files:
        rel = path.relative_to(fix_dir)
        log("info", f"  - {rel}")


def _run_fix_plan(gpt_host: str, token: str, sbom_id: str, output_dir: str,
                  poll_interval: int, max_attempts: int,
                  gos: bool = False, veecli: str = "", src_folder: str = "",
                  output_fix_dir: str = "", cli_token: str = "", gos_mode: str = "observe",
                  language: str = "", language_version: str = "",
                  connect_to_fortknox: bool = True,
                  apply_poll_interval: int = 20, apply_max_attempts: int = 60):
    """Orchestrate gos plan → fix plan request → poll → print → download.

    With gos=False the plan's own pre-signed artifacts are downloaded (the
    fix_plan mode). With gos=True that download is replaced by the GOS flow:
    the plan's components are submitted back to the GPT service, which checks
    each suggested_purl against the GOS artifactory and queues patch tasks,
    then `veecli fix --poll-tasks` waits on those tasks and writes the patched
    manifests into output_fix_dir.
    """
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

        write_raw_fix_plan(fix_data, output_dir=output_dir)

        if overall_status == "available" and not plan_details:
            log("info", fix_data.get("answer") or "No fixes available.")
            log("info", "No patch artifacts to download")
            return

        print_fix_plan(fix_data)

        if not gos:
            download_artifacts(fix_data, output_dir=output_dir)
            return

        if not plan_details:
            log("warn", "Fix plan returned no components — nothing to apply, skipping veecli fix")
            return

        write_fix_config(veecli, cli_token, gos_mode, language, language_version,
                         connect_to_fortknox=connect_to_fortknox)
        applied = apply_fix_left_plan(
            gpt_host, token, sbom_id, plan_details,
            poll_interval=apply_poll_interval,
            max_attempts=apply_max_attempts,
        )
        if not (applied.get("task_ids") or []):
            log("info", "No patch tasks were queued — skipping veecli fix (it would have "
                        "nothing to poll). No patched manifests will be produced.")
            return
        run_veecli_fix(veecli, sbom_id, src_folder, output_fix_dir, cli_token, gos_mode)
        _print_fix_dir(output_fix_dir)
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
    parser.add_argument("--language", default="", choices=["", "java", "python", "node", "dotnet", "golang", "rust"],
                        help="Language runtime to install before scanning (source scan only)")
    parser.add_argument("--language-version", default="",
                        help=(
                            "Required when --language is set. "
                            "java: Java major version (e.g. '17', '11') — "
                            "all Maven and Gradle versions are always installed. "
                            "python: Python minor (e.g. '3.11', '3.14'). "
                            "node: Node major or full (e.g. '18', '16.20.2'). "
                            "golang: Go minor version (e.g. '1.21', '1.23'). "
                            "rust: a rustup-resolvable toolchain version (e.g. '1.75.0')."
                        ))
    parser.add_argument("--src-url",      default="", help="GitHub repository URL (source scan)")
    parser.add_argument("--matching-ref", default="", help="Branch / tag / commit (source scan)")
    parser.add_argument("--fast-scan",    action="store_true", default=False, help="Pass --fast-scan to veecli")
    parser.add_argument("--gos-mode", default="observe", choices=["observe", "enforce"],
                        help="GOS premium registry mode: observe | enforce (default: observe)")
    parser.add_argument("--exclude-test-dependency",     default="true", help="Exclude test deps (source scan, true/false)")
    parser.add_argument("--exclude-optional-dependency", default="true", help="Exclude optional deps (source scan, true/false)")
    parser.add_argument("--input-json", default="/tmp/lineaje-input.json", help="Where to write input.json (source scan)")

    # auth / config (both modes)
    parser.add_argument("--refresh-token", required=True, help="Lineaje refresh token")
    parser.add_argument("--config-orig",   required=True, help="Path to config-orig.json from veecli tarball")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="Destination for generated config.json")
    parser.add_argument("--auth-service", default="", help="Identity service base URL (default: LineajeAuthService from config-orig.json)")
    parser.add_argument("--scim-host", default="", help="SCIM service base URL override (default: SCIMHost from config-orig.json)")
    parser.add_argument("--scm-host", default="", help="SCM service base URL override (default: SCMHost from config-orig.json)")
    parser.add_argument("--notification-host", default="", help="Notification service base URL override (default: NotificationServiceHost from config-orig.json)")

    # paths (both modes)
    parser.add_argument("--veecli",     default="veecli",                   help="Path to veecli binary")
    parser.add_argument("--output-dir", default="/tmp/lineaje-scan-output", help="Output directory for veecli")

    # polling (both modes)
    parser.add_argument("--poll-interval", type=int, default=30, help="Seconds between status polls")
    parser.add_argument("--max-attempts",  type=int, default=30, help="Max polling attempts")

    # optional overrides (both modes)
    parser.add_argument("--data-host",  default="", help="Data/GraphQL service base URL override (default: GraphQLServiceHost from config-orig.json)")
    parser.add_argument("--company-id", default=None, help="Company ID (auto-detected from token)")

    # fix plan (both modes)
    parser.add_argument("--gpt-host", default="", help="Lineaje GPT service base URL (default: GPTServiceHost from config, falls back to built-in prod URL)")
    parser.add_argument("--fix-plan-poll-interval", type=int, default=20, help="Seconds between fix plan polls (default: 20)")
    parser.add_argument("--fix-plan-max-attempts",  type=int, default=120, help="Max fix plan poll attempts (default: 120, ~40 min)")
    parser.add_argument("--skip-fix-plan", action="store_true", default=False, help="Skip fix plan after scan")
    parser.add_argument("--gos-fix-plan", action="store_true", default=False,
                        help="After the fix plan, apply it via the GPT service and run `veecli fix` to "
                            "download patched manifests (Python and Node.js source scans only)")
    parser.add_argument("--output-fix-dir", default="",
                        help="Where `veecli fix` writes patched manifests (default: <output-dir>/fix)")
    parser.add_argument("--no-connect-to-fortknox", action="store_true", default=False,
                        help="In --gos-fix-plan mode, never contact the Fortknox/GOS premium "
                            "registry during verification — Node.js candidate manifests are "
                            "checked against the public npm registry only, so Lineaje-rebuilt "
                            "packages fail to resolve and are excluded from what gets uploaded. "
                            "No effect on Python verification, which doesn't use Fortknox.")
    parser.add_argument("--apply-fix-poll-interval", type=int, default=20,
                        help="Seconds between polls while the GPT service queues patch tasks (default: 20)")
    parser.add_argument("--apply-fix-max-attempts", type=int, default=60,
                        help="Max polls waiting for patch tasks to be queued (default: 60, ~20 min)")

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

    # `veecli fix` patches manifests in a checked-out repo, so there is nothing
    # for it to act on in image mode.
    if args.gos_fix_plan and scan_mode != "source":
        sys.exit("[error] --gos-fix-plan is only supported for source scans")
    if args.gos_fix_plan and args.language not in {"python", "node"}:
        sys.exit("[error] --gos-fix-plan is only supported for Python and Node.js source scans")
    if args.gos_fix_plan and args.skip_fix_plan:
        sys.exit("[error] --gos-fix-plan cannot be combined with --skip-fix-plan")

    output_fix_dir = args.output_fix_dir or str(Path(args.output_dir) / "fix")

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
                "golang": f"Go minor version: {', '.join(sorted(GO_VERSIONS.keys()))}",
                "rust":   "Rust toolchain version, e.g. '1.75.0' (any version rustup recognizes)",
            }
            sys.exit(
                f"[error] --language-version is required when --language is set.\n"
                f"  Available for {args.language}: {_AVAILABLE[args.language]}"
            )

        if args.language == "java":
            setup_java_runtime(args.language_version)
            patch_runtimes_config(args.veecli, args.language_version)
            patch_tools_config_maven(args.veecli)
        elif args.language == "python":
            setup_python_runtime(args.language_version)
            patch_runtimes_config_python(args.veecli, args.language_version)
        elif args.language == "node":
            setup_node_runtime(args.language_version)
        elif args.language == "golang":
            setup_go_runtime(args.language_version)
            patch_runtimes_config_go(args.veecli, args.language_version)
            # cyclonedx-gomod v1.10+ calls `go list -mod readonly`, which
            # requires go.sum to exist. Run `go mod tidy` to generate it when
            # the project is NOT using vendor mode (vendor/ dir present means
            # -mod=vendor is implied and tidy would fail or be unnecessary).
            go_bin = THIRD_PARTY / f"go-{args.language_version}" / "bin" / "go"
            if go_bin.exists() and args.src_folder:
                vendor_dir = Path(args.src_folder) / "vendor"
                if vendor_dir.is_dir():
                    log("info", "vendor/ directory detected — skipping go mod tidy (vendor mode)")
                else:
                    log("info", f"Running go mod tidy in {args.src_folder}")
                    tidy = subprocess.run(
                        [str(go_bin), "mod", "tidy"],
                        cwd=args.src_folder,
                        capture_output=True, text=True,
                    )
                    if tidy.returncode == 0:
                        log("info", "go mod tidy succeeded — go.sum generated")
                    else:
                        log("warn", f"go mod tidy failed (non-fatal): {tidy.stderr.strip()}")
        elif args.language == "dotnet":
            log("info", f".NET {args.language_version} — runtime installed by action setup step")
        elif args.language == "rust":
            log("info", f"Rust {args.language_version} — toolchain installed by action setup step")

    # ── 1. Build config.json ───────────────────────────────────────────────────
    veecli_dir = Path(args.veecli).parent
    if Path(args.config).exists():
        log("info", "Reusing existing config.json (token already exchanged this job)")
    else:
        host_overrides = {
            "LineajeAuthService": args.auth_service,
            "SCIMHost": args.scim_host,
            "GraphQLServiceHost": args.data_host,
            "SCMHost": args.scm_host,
            "NotificationServiceHost": args.notification_host,
            "GPTServiceHost": args.gpt_host,
        }
        build_config(args.config_orig, args.refresh_token, args.config, host_overrides)
        shutil.copy2(args.config, veecli_dir / "config.json")
        log("info", f"Copied config.json to {veecli_dir}/config.json")

    # ── 2. Run veecli collect ──────────────────────────────────────────────────
    cli_token = args.refresh_token
    if scan_mode == "image":
        output = run_veecli_image(
            args.veecli, args.image, args.name, args.version,
            args.org_name, args.output_dir, args.metafiles, args.image_source_type,
            cli_token, args.gos_mode,
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
            cli_token, args.gos_mode,
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
    VULN_MAX_ATTEMPTS = 10
    VULN_POLL_INTERVAL = 15
    VULN_INITIAL_DELAY = 5

    if sbom_id and company_id:
        try:
            log("info", f"Waiting {VULN_INITIAL_DELAY}s before first vulnerability summary fetch "
                         f"to give indexing a head start...")
            time.sleep(VULN_INITIAL_DELAY)

            vuln_data = None
            indexed = False
            for attempt in range(1, VULN_MAX_ATTEMPTS + 1):
                log("info", f"Fetching vulnerability summary (attempt {attempt}/{VULN_MAX_ATTEMPTS})...")
                vuln_data = fetch_vulnerability_summary(data_host, token, company_id, sbom_id)
                if vuln_data.get("total_hits", 0) > 0:
                    indexed = True
                    break
                if attempt < VULN_MAX_ATTEMPTS:
                    log("info", f"No vulnerabilities indexed yet — retrying in {VULN_POLL_INTERVAL}s...")
                    time.sleep(VULN_POLL_INTERVAL)
            if not indexed:
                total_wait = VULN_INITIAL_DELAY + VULN_POLL_INTERVAL * (VULN_MAX_ATTEMPTS - 1)
                log("warn", f"Vulnerability data was not confirmed indexed after {VULN_MAX_ATTEMPTS} "
                             f"attempts ({total_wait}s) — the summary below may read as 0 even if the "
                             f"scan actually has findings. Re-check this SBOM later before trusting a "
                             f"clean result.")
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
        log("info", f"Requesting fix plan (scan mode: {scan_mode}"
                    f"{', GOS apply + veecli fix' if args.gos_fix_plan else ''})...")
        _run_fix_plan(
            gpt_host, token, sbom_id, args.output_dir,
            poll_interval=args.fix_plan_poll_interval,
            max_attempts=args.fix_plan_max_attempts,
            gos=args.gos_fix_plan,
            veecli=args.veecli,
            src_folder=args.src_folder,
            output_fix_dir=output_fix_dir,
            cli_token=cli_token,
            gos_mode=args.gos_mode,
            language=args.language,
            language_version=args.language_version,
            connect_to_fortknox=not args.no_connect_to_fortknox,
            apply_poll_interval=args.apply_fix_poll_interval,
            apply_max_attempts=args.apply_fix_max_attempts,
        )


if __name__ == "__main__":
    main()
