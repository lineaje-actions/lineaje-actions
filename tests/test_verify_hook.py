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


def run_python_verifier(verifier, tmp_path, *, fail_install=False, repo_root=None):
    script, fake_bin = verifier
    python3 = fake_bin / "python3"
    python3.write_text(
        "#!/usr/bin/env bash\n"
        "if [[ \"${1:-}\" = -m && \"${2:-}\" = venv ]]; then\n"
        "  mkdir -p \"$3/bin\"\n"
        "  printf 'deactivate() { :; }\\n' > \"$3/bin/activate\"\n"
        "  exit 0\n"
        "fi\n"
        "exit 2\n"
    )
    python3.chmod(0o755)
    pip = fake_bin / "pip"
    pip.write_text(
        "#!/usr/bin/env bash\n"
        "version=$(grep -m1 '^version = ' pyproject.toml 2>/dev/null || true)\n"
        "printf '%s|%s|%s\\n' \"$PWD\" \"$*\" \"$version\" >> \"$PIP_CALL_LOG\"\n"
        "if [[ \"${FAIL_PIP_INSTALL:-false}\" = true ]]; then exit 1; fi\n"
        "exit 0\n"
    )
    pip.chmod(0o755)

    task_dir = tmp_path / "python-task"
    task_dir.mkdir()
    (task_dir / "pyproject.toml").write_text(
        '[project]\nname = "fixture"\nversion = "2.0.0"\n'
    )
    call_log = tmp_path / "pip-calls.log"
    env = {
        **os.environ,
        "FAIL_PIP_INSTALL": str(fail_install).lower(),
        "PIP_CALL_LOG": str(call_log),
        "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
    }
    args = ["bash", str(script), "--task-dir", str(task_dir), "--language", "python"]
    if repo_root is not None:
        args.extend(["--repo-root", str(repo_root)])
    result = subprocess.run(
        args,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    return result, call_log.read_text() if call_log.exists() else ""


def test_python_verifier_installs_pyproject_from_reconstructed_repo(verifier, tmp_path):
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "pyproject.toml").write_text(
        '[project]\nname = "fixture"\nversion = "1.0.0"\n'
    )
    (repo_root / "fixture.py").write_text("value = 1\n")

    result, calls = run_python_verifier(verifier, tmp_path, repo_root=repo_root)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "|install .|" in calls
    assert "version = \"2.0.0\"" in calls
    install_dir = Path(calls.split("|", 1)[0])
    assert (install_dir / "fixture.py").is_file()


def test_python_verifier_propagates_pyproject_install_failure(verifier, tmp_path):
    result, calls = run_python_verifier(verifier, tmp_path, fail_install=True)

    assert result.returncode == 1
    assert "|install .|" in calls
    assert "pip install FAILED for Python project" in result.stdout
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

def run_dotnet_verifier(verifier, tmp_path, *, fail_restore=False):
    script, fake_bin = verifier
    dotnet = fake_bin / "dotnet"
    dotnet.write_text(
        "#!/usr/bin/env bash\n"
        "printf '%s\\n' \"$*\" >> \"$DOTNET_CALL_LOG\"\n"
        "if [[ \"${FAIL_DOTNET_RESTORE:-false}\" = true ]]; then exit 1; fi\n"
        "exit 0\n"
    )
    dotnet.chmod(0o755)

    project = tmp_path / "dotnet-project"
    project.mkdir()
    (project / "App.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk" />\n')
    call_log = tmp_path / "dotnet-calls.log"
    env = {
        **os.environ,
        "FAIL_DOTNET_RESTORE": str(fail_restore).lower(),
        "DOTNET_CALL_LOG": str(call_log),
        "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
    }
    result = subprocess.run(
        [
            "bash", str(script), "--task-dir", str(project), "--language", "dotnet",
            "--connect-to-fortknox", "false",
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    return result, call_log.read_text()


def test_dotnet_verifier_restores_with_warnings_not_treated_as_errors(verifier, tmp_path):
    result, calls = run_dotnet_verifier(verifier, tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    restore_calls = [line for line in calls.splitlines() if line.startswith("restore ")]
    assert len(restore_calls) == 1
    # A project with TreatWarningsAsErrors=true must not turn NuGet restore
    # warnings into failures, and a patched bump must not trip locked mode.
    assert "-p:TreatWarningsAsErrors=false" in restore_calls[0]
    assert "-p:RestoreLockedMode=false" in restore_calls[0]
    assert "--source https://api.nuget.org/v3/index.json" in restore_calls[0]
    assert "All discovered manifest files were installed successfully" in result.stdout


def test_dotnet_verifier_runs_only_restore(verifier, tmp_path):
    _result, calls = run_dotnet_verifier(verifier, tmp_path)

    # Any other dotnet command (build, list package, ...) restores implicitly and
    # would need the same property or --no-restore.
    assert all(line.startswith("restore ") for line in calls.splitlines())


def test_dotnet_verifier_propagates_restore_failure(verifier, tmp_path):
    result, _calls = run_dotnet_verifier(verifier, tmp_path, fail_restore=True)

    assert result.returncode == 1
    assert "dotnet restore FAILED" in result.stdout
    assert "One or more dependency installations failed" in result.stdout
