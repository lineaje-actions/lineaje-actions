import os
import re
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / "action.yml"
WORKFLOW = ROOT / ".github" / "workflows" / "lineaje-scan-gh.yml"


def action_fortknox_default():
    text = ACTION.read_text()
    match = re.search(
        r"(?m)^  connect_to_fortknox:\n((?:^    [^\n]*\n)+)", text
    )
    assert match
    default = re.search(r'(?m)^    default: "(true|false)"$', match.group(1))
    assert default
    return default.group(1)


def action_step_script(name):
    lines = ACTION.read_text().splitlines()
    step_start = lines.index(f"    - name: {name}")
    run_start = lines.index("      run: |", step_start) + 1
    script = []
    for line in lines[run_start:]:
        if line.startswith("        "):
            script.append(line[8:])
        elif not line.strip():
            script.append("")
        else:
            break
    return "\n".join(script)


def action_step_section(name):
    text = ACTION.read_text()
    section = text.split(f"    - name: {name}\n", 1)[1]
    return section.split("\n    - name:", 1)[0]


def test_fortknox_action_and_manual_workflow_default_to_false():
    assert action_fortknox_default() == "false"
    text = WORKFLOW.read_text()
    match = re.search(
        r"(?m)^      connect_to_fortknox:\n((?:^        [^\n]*\n)+)", text
    )
    assert match
    assert re.search(r'(?m)^        default: "false"$', match.group(1))
    assert 'options: ["false", "true"]' in match.group(1)
    assert re.search(
        r"(?m)^          connect_to_fortknox:\s+\$\{\{ inputs\.connect_to_fortknox \}\}$",
        text,
    )


@pytest.mark.parametrize(
    ("setting", "disabled"),
    [(None, True), ("false", True), ("true", False)],
)
def test_gos_compat_passes_fortknox_setting_to_python(setting, disabled):
    for step in ("Validate source scan inputs", "Lineaje scan"):
        assert (
            "CONNECT_TO_FORTKNOX: ${{ inputs.connect_to_fortknox }}"
            in action_step_section(step)
        )
    script = action_step_script("Lineaje scan")
    block = re.search(
        r'(?ms)^if \[ "\$EFFECTIVE" = "scan_only" \]; then\n.*?^fi$', script
    )
    assert block
    env = {
        **os.environ,
        "EFFECTIVE": "fix_plan_gos_compat",
        "CONNECT_TO_FORTKNOX": action_fortknox_default() if setting is None else setting,
        "OUTPUT_FIX_DIR": "/tmp/fix",
    }
    result = subprocess.run(
        ["bash", "-e", "-c", 'SCAN_ARGS=()\n' + block.group() + '\nprintf "%s\\n" "${SCAN_ARGS[@]}"'],
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    arguments = result.stdout.splitlines()
    assert "--gos-fix-plan" in arguments
    assert ("--no-connect-to-fortknox" in arguments) is disabled


@pytest.mark.parametrize(
    ("setting", "valid"),
    [("false", True), ("true", True), ("", False), ("FALSE", False), ("no", False)],
)
def test_gos_compat_rejects_invalid_fortknox_values(tmp_path, setting, valid):
    env = {
        **os.environ,
        "LANGUAGE": "python",
        "LANGUAGE_VERSION": "3.12",
        "POST_SCAN": "fix_plan_gos_compat",
        "CONNECT_TO_FORTKNOX": setting,
        "GITHUB_ENV": str(tmp_path / "github-env"),
    }
    result = subprocess.run(
        ["bash", "-e", "-c", action_step_script("Validate source scan inputs")],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert (result.returncode == 0) is valid
    if not valid:
        assert "'connect_to_fortknox' must be 'true' or 'false'" in result.stdout


@pytest.mark.parametrize("post_scan", ["scan_only", "fix_plan"])
def test_other_post_scan_modes_ignore_fortknox_setting(tmp_path, post_scan):
    env = {
        **os.environ,
        "LANGUAGE": "python",
        "LANGUAGE_VERSION": "3.12",
        "POST_SCAN": post_scan,
        "CONNECT_TO_FORTKNOX": "",
        "GITHUB_ENV": str(tmp_path / "github-env"),
    }
    result = subprocess.run(
        ["bash", "-e", "-c", action_step_script("Validate source scan inputs")],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
