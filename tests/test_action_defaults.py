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


def read_step_outputs(path):
    outputs = {}
    lines = path.read_text().split("\n")
    if lines[-1] == "":
        lines.pop()
    index = 0
    while index < len(lines):
        if "<<" not in lines[index]:
            name, value = lines[index].split("=", 1)
            outputs[name] = value
            index += 1
            continue
        name, delimiter = lines[index].split("<<", 1)
        index += 1
        value = []
        while lines[index] != delimiter:
            value.append(lines[index])
            index += 1
        outputs[name] = "\n".join(value)
        index += 1
    return outputs


def prepare_artifact_names(tmp_path, scan_type, version):
    output = tmp_path / "artifact-names"
    output.write_text("")
    subprocess.run(
        ["bash", "-e", "-c", action_step_script("Prepare artifact names")],
        env={
            **os.environ,
            "GITHUB_OUTPUT": str(output),
            "SCAN_TYPE": scan_type,
            "PROJECT_VERSION": version,
        },
        text=True,
        capture_output=True,
        check=True,
    )
    return read_step_outputs(output)


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


@pytest.mark.parametrize(
    ("scan_type", "version", "expected_version"),
    [
        ("image", "image-42-1", "image-42-1"),
        ("source", "release-source-42-1-services-api", "release-source-42-1-services-api"),
        ("source", "explicit-version", "explicit-version"),
        ("source", "source-42-2-patched", "source-42-2-patched"),
        ("source", "version \t\u00a0\ufeff", "version"),
        ("source", "version\u0085", "version\u0085"),
        ("source", "version\nunexpected=output", "version\nunexpected=output"),
    ],
)
def test_artifact_names_match_upload_input_trimming(
    tmp_path, scan_type, version, expected_version
):
    names = prepare_artifact_names(tmp_path, scan_type, version)

    assert names == {
        "image_fix": f"image-patched-dockerfile-{expected_version}",
        "source_fix": f"source-lineaje-fix-plan-{expected_version}",
        "source_gos_fix": f"source-lineaje-fix-plan-gos-{expected_version}",
        "raw_fix_plan": f"{scan_type}-lineaje-raw-fix-plan-{expected_version}",
    }


@pytest.mark.parametrize(
    ("project_version", "version_prefix", "source_dir", "previous_scans", "expected_version"),
    [
        ("", "api", "services/api", "", "api-source-42-2-services-api"),
        ("custom", "ignored", "services/api", "", "custom"),
        ("", "", ".", "image,source", "source-42-2-patched"),
    ],
)
def test_artifact_names_use_resolved_scan_version(
    tmp_path, project_version, version_prefix, source_dir, previous_scans, expected_version
):
    env_file = tmp_path / "github-env"
    env_file.write_text("")
    if previous_scans:
        (tmp_path / ".lineaje_previous_scan_types").write_text(previous_scans)
    env = {
        **os.environ,
        "GITHUB_ENV": str(env_file),
        "GITHUB_WORKSPACE": str(tmp_path),
        "MATCHING_REF_INPUT": "main",
        "METAFILES_INPUT": "",
        "OUTPUT_DIR_INPUT": "/tmp/lineaje-scan-output",
        "PROJECT_NAME_INPUT": "project",
        "PROJECT_VERSION_INPUT": project_version,
        "REPOSITORY": "example/project",
        "RUN_ATTEMPT": "2",
        "RUN_NUMBER": "42",
        "SCAN_TYPE": "source",
        "SERVER_URL": "https://github.com",
        "SOURCE_DIR_INPUT": source_dir,
        "VEECLI_ALREADY_SETUP": "true" if previous_scans else "false",
        "VERSION_PREFIX": version_prefix,
    }
    subprocess.run(
        ["bash", "-e", "-c", action_step_script("Set scan env vars")],
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    resolved_version = read_step_outputs(env_file)["PROJECT_VERSION"]
    assert resolved_version == expected_version
    names = prepare_artifact_names(tmp_path, "source", resolved_version)
    assert names["source_gos_fix"] == f"source-lineaje-fix-plan-gos-{expected_version}"


def test_artifact_uploads_and_public_outputs_are_wired_to_internal_steps():
    outputs = ACTION.read_text().split("\noutputs:\n", 1)[1].split("\nruns:", 1)[0]
    assert "value: ${{ steps.artifact_outputs.outputs.fix_artifact_name }}" in outputs
    assert "value: ${{ steps.artifact_outputs.outputs.raw_fix_plan_artifact_name }}" in outputs

    upload_steps = [
        ("Upload patched Dockerfile", "upload_image_fix", "image_fix"),
        ("Upload fix plan artifacts", "upload_source_fix", "source_fix"),
        ("Upload GOS fix artifacts", "upload_source_gos_fix", "source_gos_fix"),
        ("Upload raw fix plan", "upload_raw_fix_plan", "raw_fix_plan"),
    ]
    for step, step_id, name_output in upload_steps:
        section = action_step_section(step)
        assert f"id: {step_id}" in section
        assert "uses: actions/upload-artifact@v4" in section
        assert f"name: ${{{{ steps.artifact_names.outputs.{name_output} }}}}" in section
        assert "if-no-files-found: ignore" in section

    section = action_step_section("Set artifact outputs")
    for env_key, step_id, name_output in [
        ("IMAGE_FIX", "upload_image_fix", "image_fix"),
        ("SOURCE_FIX", "upload_source_fix", "source_fix"),
        ("SOURCE_GOS_FIX", "upload_source_gos_fix", "source_gos_fix"),
        ("RAW_FIX_PLAN", "upload_raw_fix_plan", "raw_fix_plan"),
    ]:
        assert f"{env_key}_ID: ${{{{ steps.{step_id}.outputs.artifact-id }}}}" in section
        assert f"{env_key}_NAME: ${{{{ steps.artifact_names.outputs.{name_output} }}}}" in section


@pytest.mark.parametrize(
    ("scan_type", "uploaded_fix", "uploaded_raw"),
    [
        ("image", "image_fix", True),
        ("source", "source_fix", True),
        ("source", "source_gos_fix", True),
        ("source", "source_gos_fix", False),
        ("source", None, True),
        ("image", None, False),
    ],
)
def test_artifact_outputs_only_report_successfully_uploaded_artifacts(
    tmp_path, scan_type, uploaded_fix, uploaded_raw
):
    names = prepare_artifact_names(tmp_path, scan_type, "custom-42-patched")
    output = tmp_path / "artifact-outputs"
    output.write_text("")
    env = {
        **os.environ,
        "GITHUB_OUTPUT": str(output),
        "IMAGE_FIX_ID": "101" if uploaded_fix == "image_fix" else "",
        "SOURCE_FIX_ID": "102" if uploaded_fix == "source_fix" else "",
        "SOURCE_GOS_FIX_ID": "103" if uploaded_fix == "source_gos_fix" else "",
        "RAW_FIX_PLAN_ID": "104" if uploaded_raw else "",
        "IMAGE_FIX_NAME": names["image_fix"],
        "SOURCE_FIX_NAME": names["source_fix"],
        "SOURCE_GOS_FIX_NAME": names["source_gos_fix"],
        "RAW_FIX_PLAN_NAME": names["raw_fix_plan"],
    }
    subprocess.run(
        ["bash", "-e", "-c", action_step_script("Set artifact outputs")],
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )

    expected = {}
    if uploaded_fix:
        expected["fix_artifact_name"] = names[uploaded_fix]
    if uploaded_raw:
        expected["raw_fix_plan_artifact_name"] = names["raw_fix_plan"]
    assert read_step_outputs(output) == expected


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"IMAGE_FIX_ID": "101"}, "uploaded artifact name is missing"),
        ({"RAW_FIX_PLAN_ID": "104"}, "uploaded artifact name is missing"),
        (
            {"IMAGE_FIX_ID": "101", "IMAGE_FIX_NAME": "image\nunexpected=output"},
            "uploaded artifact name contains a line break",
        ),
        (
            {"IMAGE_FIX_ID": "101", "SOURCE_FIX_ID": "102"},
            "multiple patched artifacts were uploaded",
        ),
    ],
)
def test_artifact_outputs_reject_inconsistent_upload_state(tmp_path, overrides, error):
    output = tmp_path / "artifact-outputs"
    output.write_text("")
    env = {
        **os.environ,
        "GITHUB_OUTPUT": str(output),
        "IMAGE_FIX_ID": "",
        "SOURCE_FIX_ID": "",
        "SOURCE_GOS_FIX_ID": "",
        "RAW_FIX_PLAN_ID": "",
        "IMAGE_FIX_NAME": "",
        "SOURCE_FIX_NAME": "",
        "SOURCE_GOS_FIX_NAME": "",
        "RAW_FIX_PLAN_NAME": "",
        **overrides,
    }
    result = subprocess.run(
        ["bash", "-e", "-c", action_step_script("Set artifact outputs")],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert error in result.stderr
