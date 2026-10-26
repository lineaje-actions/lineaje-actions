import os
import shutil
import subprocess
from pathlib import Path

import pytest


VERIFY_SCRIPT = Path(__file__).resolve().parents[1] / "lineaje-verify.sh"


@pytest.fixture
def verifier(tmp_path):
    script_dir = tmp_path / "verifier"
    script_dir.mkdir()
    script = script_dir / "lineaje-verify.sh"
    shutil.copy2(VERIFY_SCRIPT, script)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    npm = fake_bin / "npm"
    npm.write_text(
        "#!/usr/bin/env bash\n"
        "printf '%s\\n' \"$*\" >> \"$NPM_CALL_LOG\"\n"
        "if [[ \"${FAIL_NPM_INSTALL:-false}\" = true && \"${1:-}\" = install ]]; then exit 1; fi\n"
        "exit 0\n"
    )
    npm.chmod(0o755)
    return script, fake_bin


def run_node_verifier(verifier, tmp_path, *, fail_install=False):
    script, fake_bin = verifier
    project = tmp_path / "project"
    project.mkdir()
    (project / "package.json").write_text('{"name":"fixture","version":"1.0.0"}\n')
    call_log = tmp_path / "npm-calls.log"
    env = {
        **os.environ,
        "FAIL_NPM_INSTALL": str(fail_install).lower(),
        "NPM_CALL_LOG": str(call_log),
        "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
    }
    result = subprocess.run(
        [
            "bash", str(script), "--task-dir", str(project), "--language", "node",
            "--connect-to-fortknox", "false",
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    return result, call_log.read_text()


def test_node_verifier_uses_public_registry_and_validates_tree(verifier, tmp_path):
    result, calls = run_node_verifier(verifier, tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "install --registry https://registry.npmjs.org/" in calls
    assert "ls --all --json" in calls
    assert "All discovered manifest files were installed successfully" in result.stdout


def test_node_verifier_propagates_install_failure(verifier, tmp_path):
    result, calls = run_node_verifier(verifier, tmp_path, fail_install=True)

    assert result.returncode == 1
    assert "install --registry https://registry.npmjs.org/" in calls
    assert "npm install FAILED" in result.stdout
    assert "One or more dependency installations failed" in result.stdout


def test_go_verifier_explains_newer_standard_library_requirement(verifier, tmp_path):
    script, _fake_bin = verifier
    project = tmp_path / "go-project"
    project.mkdir()
    (project / "go.mod").write_text("module example.com/fixture\n\ngo 1.18\n")
    (project / "main.go").write_text("package main\n\nfunc main() {}\n")

    go_bin = tmp_path / "go-bin"
    go_bin.mkdir()
    fake_go = go_bin / "go"
    fake_go.write_text(
        "#!/usr/bin/env bash\n"
        "if [[ \"${1:-}\" = version ]]; then echo 'go version go1.18.10 linux/amd64'; exit 0; fi\n"
        "echo '/module/cache/golang.org/x/crypto@v0.31.0/curve25519/curve25519.go:13:8: package crypto/ecdh is not in GOROOT (/go/src/crypto/ecdh)'\n"
        "exit 1\n"
    )
    fake_go.chmod(0o755)

    result = subprocess.run(
        [
            "bash", str(script), "--task-dir", str(project), "--language", "golang",
            "--go-bin-dir", str(go_bin),
        ],
        env=os.environ.copy(),
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1
    assert "go version go1.18.10 linux/amd64" in result.stdout
    assert "unavailable in the pinned toolchain" in result.stdout
    assert "crypto/ecdh" in result.stdout
    assert "Raise the action's language_version" in result.stdout