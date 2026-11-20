import io
import os
import re
import shlex
import subprocess
import tarfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / "action.yml"
WORKFLOW = ROOT / ".github" / "workflows" / "lineaje-scan-gh.yml"


def action_boolean_default(name):
    text = ACTION.read_text()
    match = re.search(
        rf"(?m)^  {re.escape(name)}:\n((?:^    [^\n]*\n)+)", text
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
    assert action_boolean_default("connect_to_fortknox") == "false"
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


def test_debug_action_and_manual_workflow_default_to_false():
    assert action_boolean_default("enable_debug") == "false"
    assert (
        "ENABLE_DEBUG: ${{ inputs.enable_debug }}"
        in action_step_section("Download and extract veecli")
    )
    text = WORKFLOW.read_text()
    match = re.search(r"(?m)^      enable_debug:\n((?:^        [^\n]*\n)+)", text)
    assert match
    assert re.search(r'(?m)^        default: "false"$', match.group(1))
    assert 'options: ["false", "true"]' in match.group(1)
    assert re.search(
        r"(?m)^          enable_debug:\s+\$\{\{ inputs\.enable_debug \}\}$", text
    )


def write_cli_archive(path, variant, omitted=()):
    members = {
        "veecli": f"{variant} binary\n".encode(),
        "config-orig.json": f"{variant} config\n".encode(),
        "pre.sh": b"#!/bin/sh\n",
    }
    mode = "w:gz" if variant == "standard" else "w:"
    with tarfile.open(path, mode) as archive:
        for name, content in members.items():
            if name in omitted:
                continue
            info = tarfile.TarInfo(f"veecli/{name}")
            info.mode = 0o644
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))


@pytest.fixture
def cli_download(tmp_path):
    archives = {
        "standard": tmp_path / "standard.tar.gz",
        "debug": tmp_path / "debug.tar",
    }
    for variant, path in archives.items():
        write_cli_archive(path, variant)

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    curl = bin_dir / "curl"
    curl.write_text(
        """#!/bin/bash
printf '%s\\n' "$2" >> "$MOCK_CURL_LOG"
if [ "${MOCK_CURL_FAIL:-}" = "true" ]; then
  echo "mock download failed" >&2
  exit 22
fi
case "$2" in
  https://downloads.prod.veedna.com/veecli_latest.tar.gz)
    archive="$MOCK_STANDARD_ARCHIVE"
    ;;
  https://downloads.prod.veedna.com/veecli_debug.tar.gz)
    archive="$MOCK_DEBUG_ARCHIVE"
    ;;
  *)
    echo "unexpected download URL: $2" >&2
    exit 1
    ;;
esac
[ "$1" = "-fL" ] && [ "$3" = "-o" ] || exit 1
cp "$archive" "$4"
"""
    )
    curl.chmod(0o755)
    env_file = tmp_path / "github-env"
    env_file.write_text("")
    log = tmp_path / "downloads"
    log.write_text("")
    link = tmp_path / "opt" / "veecli"
    link.parent.mkdir()
    script = action_step_script("Download and extract veecli")
    script = script.replace("/opt/veecli", shlex.quote(str(link)))
    script = script.replace(
        "/tmp/veecli-extract-XXXXXX",
        shlex.quote(str(tmp_path / "veecli-extract-XXXXXX")),
    )
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "GITHUB_ENV": str(env_file),
        "LINEAJE_ACTION_SETUP_COMPLETE": "",
        "LINEAJE_VEECLI_VARIANT": "",
        "MOCK_CURL_FAIL": "",
        "MOCK_CURL_LOG": str(log),
        "MOCK_DEBUG_ARCHIVE": str(archives["debug"]),
        "MOCK_STANDARD_ARCHIVE": str(archives["standard"]),
        "VEECLI_ALREADY_SETUP": "",
        "VEECLI_PREVIOUSLY_SETUP": "",
    }
    return {
        "archives": archives,
        "env": env,
        "env_file": env_file,
        "link": link,
        "log": log,
        "script": script,
    }


def run_cli_download(state, setting):
    state["env_file"].write_text("")
    state["env"]["ENABLE_DEBUG"] = setting
    result = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", state["script"]],
        env=state["env"],
        text=True,
        capture_output=True,
        check=False,
    )
    state["env"].update(read_step_outputs(state["env_file"]))
    return result


def finish_cli_setup(state):
    link = state["link"]
    if link.is_symlink():
        link.unlink()
    link.symlink_to(Path(state["env"]["VEECLI_PATH"]).parent, target_is_directory=True)
    state["env"]["LINEAJE_ACTION_SETUP_COMPLETE"] = "true"


@pytest.mark.parametrize(
    ("setting", "variant"),
    [(None, "standard"), ("false", "standard"), ("true", "debug")],
)
def test_download_selects_build_and_extracts_its_archive(cli_download, setting, variant):
    setting = action_boolean_default("enable_debug") if setting is None else setting
    result = run_cli_download(cli_download, setting)
    assert result.returncode == 0, result.stdout + result.stderr

    env = cli_download["env"]
    suffix = "latest" if variant == "standard" else "debug"
    assert cli_download["log"].read_text().splitlines() == [
        f"https://downloads.prod.veedna.com/veecli_{suffix}.tar.gz"
    ]
    assert env["LINEAJE_VEECLI_VARIANT"] == variant
    assert env["LINEAJE_ACTION_SETUP_COMPLETE"] == "false"
    assert env["VEECLI_ALREADY_SETUP"] == "false"
    assert env["VEECLI_PREVIOUSLY_SETUP"] == "false"
    binary = Path(env["VEECLI_PATH"])
    assert binary.read_text() == f"{variant} binary\n"
    assert os.access(binary, os.X_OK)
    assert Path(env["CONFIG_ORIG_PATH"]).read_text() == f"{variant} config\n"
    assert list(binary.parent.parent.glob("veecli.tar*")) == []


@pytest.mark.parametrize("setting", ["", "TRUE", "False", "yes", "1"])
def test_download_rejects_invalid_debug_values(cli_download, setting):
    result = run_cli_download(cli_download, setting)
    assert result.returncode != 0
    assert "'enable_debug' must be 'true' or 'false'" in result.stdout
    assert cli_download["log"].read_text() == ""


@pytest.mark.parametrize(
    "settings",
    [
        ["false", "false", "true", "true", "false", "false"],
        ["true", "true", "false", "true"],
    ],
)
def test_download_reuses_only_matching_builds(cli_download, settings):
    previous = None
    expected_downloads = []
    for setting in settings:
        variant = "debug" if setting == "true" else "standard"
        result = run_cli_download(cli_download, setting)
        assert result.returncode == 0, result.stdout + result.stderr
        env = cli_download["env"]
        reused = variant == previous
        assert env["VEECLI_PREVIOUSLY_SETUP"] == ("false" if previous is None else "true")
        assert env["VEECLI_ALREADY_SETUP"] == ("true" if reused else "false")
        assert env["LINEAJE_VEECLI_VARIANT"] == variant
        assert Path(env["VEECLI_PATH"]).read_text() == f"{variant} binary\n"
        assert Path(env["CONFIG_ORIG_PATH"]).read_text() == f"{variant} config\n"

        if not reused:
            assert env["LINEAJE_ACTION_SETUP_COMPLETE"] == "false"
            expected_downloads.append(
                f"https://downloads.prod.veedna.com/veecli_{'debug' if setting == 'true' else 'latest'}.tar.gz"
            )
            finish_cli_setup(cli_download)
        assert (cli_download["link"] / "veecli").read_text() == f"{variant} binary\n"
        previous = variant

    assert cli_download["log"].read_text().splitlines() == expected_downloads


@pytest.mark.parametrize("failure", ["download", "corrupt", "missing-binary", "missing-config"])
def test_failed_build_switch_does_not_leave_setup_marked_complete(cli_download, failure):
    result = run_cli_download(cli_download, "false")
    assert result.returncode == 0, result.stdout + result.stderr
    finish_cli_setup(cli_download)
    result = run_cli_download(cli_download, "false")
    assert result.returncode == 0, result.stdout + result.stderr
    assert cli_download["env"]["VEECLI_ALREADY_SETUP"] == "true"

    if failure == "download":
        cli_download["env"]["MOCK_CURL_FAIL"] = "true"
    elif failure == "corrupt":
        cli_download["archives"]["debug"].write_bytes(b"not an archive")
    else:
        omitted = ("veecli",) if failure == "missing-binary" else ("config-orig.json",)
        write_cli_archive(cli_download["archives"]["debug"], "debug", omitted)

    result = run_cli_download(cli_download, "true")
    assert result.returncode != 0
    expected_error = {
        "download": "mock download failed",
        "corrupt": "tar",
        "missing-binary": "veecli binary not found after extraction",
        "missing-config": "config-orig.json not found after extraction",
    }[failure]
    assert expected_error in result.stdout + result.stderr
    env = cli_download["env"]
    assert env["LINEAJE_ACTION_SETUP_COMPLETE"] == "false"
    assert env["LINEAJE_VEECLI_VARIANT"] == "standard"
    assert env["VEECLI_ALREADY_SETUP"] == "false"
    assert env["VEECLI_PREVIOUSLY_SETUP"] == "true"
    assert (cli_download["link"] / "veecli").read_text() == "standard binary\n"

    cli_download["env"]["MOCK_CURL_FAIL"] = ""
    write_cli_archive(cli_download["archives"]["debug"], "debug")
    result = run_cli_download(cli_download, "true")
    assert result.returncode == 0, result.stdout + result.stderr
    assert env["VEECLI_ALREADY_SETUP"] == "false"
    assert env["VEECLI_PREVIOUSLY_SETUP"] == "true"
    assert Path(env["VEECLI_PATH"]).read_text() == "debug binary\n"


@pytest.mark.parametrize("state_change", ["unknown-variant", "missing-binary"])
def test_download_does_not_reuse_unknown_or_missing_build(cli_download, state_change):
    result = run_cli_download(cli_download, "false")
    assert result.returncode == 0, result.stdout + result.stderr
    finish_cli_setup(cli_download)
    result = run_cli_download(cli_download, "false")
    assert result.returncode == 0, result.stdout + result.stderr
    assert cli_download["env"]["VEECLI_ALREADY_SETUP"] == "true"

    if state_change == "unknown-variant":
        cli_download["env"]["LINEAJE_VEECLI_VARIANT"] = ""
    else:
        Path(cli_download["env"]["VEECLI_PATH"]).unlink()

    result = run_cli_download(cli_download, "false")
    assert result.returncode == 0, result.stdout + result.stderr
    assert cli_download["env"]["VEECLI_ALREADY_SETUP"] == "false"
    assert cli_download["env"]["VEECLI_PREVIOUSLY_SETUP"] == "true"
    assert cli_download["env"]["LINEAJE_ACTION_SETUP_COMPLETE"] == "false"
    assert len(cli_download["log"].read_text().splitlines()) == 2


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
        "CONNECT_TO_FORTKNOX": action_boolean_default("connect_to_fortknox") if setting is None else setting,
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
    (
        "project_version", "version_prefix", "source_dir", "previous_scans",
        "previously_setup", "already_setup", "expected_version",
    ),
    [
        ("", "api", "services/api", "", False, False, "api-source-42-2-services-api"),
        ("custom", "ignored", "services/api", "", False, False, "custom"),
        ("", "", ".", "image,source", True, True, "source-42-2-patched"),
        ("", "", ".", "image,source", True, False, "source-42-2-patched"),
        ("", "", ".", "source", False, False, "source-42-2"),
        ("", "", ".", "image", True, False, "source-42-2"),
    ],
)
def test_artifact_names_use_resolved_scan_version(
    tmp_path, project_version, version_prefix, source_dir, previous_scans,
    previously_setup, already_setup, expected_version,
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
        "VEECLI_ALREADY_SETUP": "true" if already_setup else "false",
        "VEECLI_PREVIOUSLY_SETUP": "true" if previously_setup else "false",
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
