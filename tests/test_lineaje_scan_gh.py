import base64
import copy
import stat
import sys
from pathlib import Path

import pytest
import requests

import lineaje_scan_gh as scan


TEST_COMPANY_ID = "vdna_test-company"
TEST_SBOM_ID = "SPDXRef-DOCUMENT-vdna_test-123-456"
TEST_PROJECT_URL = (
    f"https://app.veedna.com/{TEST_COMPANY_ID}/SBOM360/projects/{TEST_SBOM_ID}/info"
)


class FakeResponse:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        return None

    def json(self):
        return self._data


def test_parse_job_id_extracts_numeric_suffix():
    assert scan.parse_job_id("collect complete: SBOM ID - tenant-project-12345") == "12345"


@pytest.mark.parametrize("output", ["no identifier", "SBOM ID - missing-numeric-suffix"])
def test_parse_job_id_rejects_unusable_output(output):
    with pytest.raises(SystemExit):
        scan.parse_job_id(output)


def test_action_pip_environment_omits_customer_extra_index(monkeypatch):
    monkeypatch.setenv("PIP_EXTRA_INDEX_URL", "https://private.example/simple")
    monkeypatch.setenv("PIP_CACHE_DIR", "/tmp/pip-cache")

    env = scan._action_pip_env()

    assert "PIP_EXTRA_INDEX_URL" not in env
    assert env["PIP_CACHE_DIR"] == "/tmp/pip-cache"


def test_parse_vulnerability_summary_ignores_fix_plan_aggregate():
    log_text = """\
[12:00:00] [info] VULNERABILITY SUMMARY
[12:00:00] [info] ==================================================
[12:00:00] [info]   Total:     30
[12:00:00] [info]   Critical:  1
[12:00:00] [info]   High:      11
[12:00:00] [info]   Medium:    17
[12:00:00] [info]   Low:       1
[12:00:00] [info]   Exploited: 0
[12:00:00] [info] ==================================================
[12:01:00] [info]   Critical: 1  High: 11  Medium: 0  Low: 0
"""

    assert scan.parse_vulnerability_summary(log_text) == {
        "Exploited": 0,
        "Critical": 1,
        "High": 11,
    }


def test_parse_vulnerability_summary_requires_dedicated_summary_block():
    assert scan.parse_vulnerability_summary(
        "[12:00:00] [info] Critical: 1  High: 11  Medium: 0  Low: 0\n"
    ) is None


@pytest.mark.parametrize(
    ("reported_count", "expected_alert", "expected_notice"),
    [
        ("1", True, False),
        (1, True, False),
        (" 1 ", True, False),
        ("2", False, True),
        (2, False, True),
        ("4", False, True),
        (" 13 ", False, True),
        (0, False, False),
        (None, False, False),
        ("unknown", False, False),
        (True, False, False),
    ],
)
def test_unconfirmed_vulnerability_summary_reports_component_conditions(
    tmp_path, monkeypatch, capsys, reported_count, expected_alert, expected_notice
):
    summary_path = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))
    updates = {}
    if reported_count is not None:
        updates["Cli:Total No. of Unique Components discovered"] = reported_count

    scan._warn_unconfirmed_vulnerability_summary(
        attempts=10,
        total_wait=140,
        job_result={"job_status_updates": updates},
        vuln_data={"total_hits": 0},
        company_id=TEST_COMPANY_ID,
        sbom_id=TEST_SBOM_ID,
    )

    output = capsys.readouterr().out
    assert "Vulnerability data was not confirmed indexed" in output
    assert ("::warning title=Lineaje scan may be incomplete::" in output) is expected_alert
    assert summary_path.exists() is (expected_alert or expected_notice)
    if expected_alert:
        assert "one unique component" in output
        guidance = (
            "Review the SBOM component and dependency inventory in the Lineaje Portal "
            f"({TEST_PROJECT_URL}) before treating ECH=0 as clean."
        )
        annotation = next(
            line for line in output.splitlines()
            if line.startswith("::warning title=Lineaje scan may be incomplete::")
        )
        assert guidance in annotation
        assert guidance in summary_path.read_text()
    elif expected_notice:
        summary = summary_path.read_text()
        assert f"reported {int(reported_count)} unique components" in summary
        assert "summary returned no records after 10 attempts (140s)" in summary
        guidance = (
            "Review the project's vulnerability results in the Lineaje Portal "
            f"({TEST_PROJECT_URL}) to confirm before treating ECH=0 as clean."
        )
        assert guidance in summary
        assert guidance in output
        assert "Potentially incomplete scan" not in summary
    elif reported_count is None or reported_count == "unknown" or reported_count is True:
        assert "Could not determine" in output


@pytest.mark.parametrize("component_count", ["1", "2"])
@pytest.mark.parametrize(
    "vuln_data",
    [None, {}, {"total_hits": "0"}, {"total_hits": False}, {"total_hits": -1}],
)
def test_unconfirmed_summary_does_not_assume_missing_or_invalid_total_is_zero(
    tmp_path, monkeypatch, capsys, vuln_data, component_count
):
    summary_path = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))

    scan._warn_unconfirmed_vulnerability_summary(
        attempts=10,
        total_wait=140,
        job_result={
            "job_status_updates": {"Cli:Total No. of Unique Components discovered": component_count}
        },
        vuln_data=vuln_data,
        company_id=TEST_COMPANY_ID,
        sbom_id=TEST_SBOM_ID,
    )

    output = capsys.readouterr().out
    assert "Could not determine whether the vulnerability summary contains zero records" in output
    assert "::warning title=Lineaje scan may be incomplete::" not in output
    assert not summary_path.exists()


@pytest.mark.parametrize("component_count", ["1", "2"])
def test_unconfirmed_summary_is_plain_log_outside_github_actions(
    monkeypatch, capsys, component_count
):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

    scan._warn_unconfirmed_vulnerability_summary(
        attempts=10,
        total_wait=140,
        job_result={
            "job_status_updates": {"Cli:Total No. of Unique Components discovered": component_count}
        },
        vuln_data={"total_hits": 0},
        company_id=TEST_COMPANY_ID,
        sbom_id=TEST_SBOM_ID,
    )

    output = capsys.readouterr().out
    expected_count = "one" if component_count == "1" else "2"
    assert f"{expected_count} unique component" in output
    assert f"Lineaje Portal ({TEST_PROJECT_URL})" in output
    assert "::warning" not in output


@pytest.mark.parametrize("component_count", ["1", "2"])
def test_unconfirmed_summary_encodes_project_url(tmp_path, monkeypatch, capsys, component_count):
    summary_path = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))

    scan._warn_unconfirmed_vulnerability_summary(
        attempts=10,
        total_wait=140,
        job_result={
            "job_status_updates": {"Cli:Total No. of Unique Components discovered": component_count}
        },
        vuln_data={"total_hits": 0},
        company_id="company/with %\n",
        sbom_id="sbom?part#%",
    )

    expected_url = (
        "https://app.veedna.com/company%2Fwith%20%25%0A/"
        "SBOM360/projects/sbom%3Fpart%23%25/info"
    )
    output = capsys.readouterr().out
    if component_count == "1":
        annotation = next(
            line for line in output.splitlines()
            if line.startswith("::warning title=Lineaje scan may be incomplete::")
        )
        annotation_message = (
            annotation.split("::", 2)[2]
            .replace("%0D", "\r")
            .replace("%0A", "\n")
            .replace("%25", "%")
        )
        assert expected_url in annotation_message
        assert "\n" not in annotation_message
    else:
        assert "::warning title=Lineaje scan may be incomplete::" not in output
    assert expected_url in summary_path.read_text()
    assert expected_url in output


@pytest.mark.parametrize("scan_mode", ["source", "image"])
@pytest.mark.parametrize(
    ("company_arg", "expected_company_id"),
    [(None, "vdna_from_token"), ("vdna_override", "vdna_override")],
)
@pytest.mark.parametrize(
    ("component_count", "total_hits", "expected_alert", "expected_notice"),
    [
        ("1", 0, True, False),
        ("2", 0, False, True),
        ("4", 0, False, True),
        ("13", 0, False, True),
        ("0", 0, False, False),
        (None, 0, False, False),
        ("1", 1, False, False),
        ("13", 1, False, False),
    ],
)
def test_main_reports_unconfirmed_zero_vulnerability_results(
    tmp_path, monkeypatch, capsys, component_count, total_hits, expected_alert, expected_notice,
    company_arg, expected_company_id, scan_mode
):
    veecli_dir = tmp_path / "veecli"
    veecli_dir.mkdir()
    config = tmp_path / "config.json"
    summary = tmp_path / "summary.md"
    updates = {}
    if component_count is not None:
        updates["Cli:Total No. of Unique Components discovered"] = component_count
    job = {
        "result": {
            "job_status": "Ready for review",
            "sbom_id": TEST_SBOM_ID,
            "job_status_updates": updates,
        }
    }
    waits = []
    fetches = []
    token_payload = base64.urlsafe_b64encode(
        b'{"user_metadata":{"company_id":"vdna_from_token"}}'
    ).decode().rstrip("=")
    org_token = f"header.{token_payload}.signature"
    initial_payload = base64.urlsafe_b64encode(
        b'{"user_metadata":{"company_id":"vdna_before_collect"}}'
    ).decode().rstrip("=")
    auth_tokens = iter([f"header.{initial_payload}.signature", org_token])
    company_args = ["--company-id", company_arg] if company_arg else []
    scan_args = (
        ["--src-folder", str(tmp_path), "--src-url", "https://example.com/repo",
         "--matching-ref", "main"]
        if scan_mode == "source" else ["--image", "example-image"]
    )

    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "lineaje_scan_gh.py", "--name", "project", "--version", "1",
            "--org-name", "org", "--refresh-token", "token",
            "--config-orig", str(tmp_path / "config-orig.json"), "--config", str(config),
            "--veecli", str(veecli_dir / "veecli"), "--output-dir", str(tmp_path / "out"),
            *scan_args, *company_args, "--skip-fix-plan",
        ],
    )
    monkeypatch.setattr(
        scan, "build_config", lambda _orig, _refresh, path, _overrides: Path(path).write_text("{}")
    )
    monkeypatch.setattr(scan, "get_auth_token", lambda _cfg: next(auth_tokens))
    monkeypatch.setattr(scan, "validate_org_matches_token", lambda *_args: None)
    monkeypatch.setattr(scan, "get_scim_host", lambda _cfg: "https://scim.example")
    monkeypatch.setattr(scan, "get_data_host", lambda *_args: "https://data.example")
    monkeypatch.setattr(scan, "get_gpt_host", lambda *_args: "https://gpt.example")
    monkeypatch.setattr(scan, "write_input_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(scan, "run_veecli_source", lambda *_args: "SBOM ID - project-42")
    monkeypatch.setattr(scan, "run_veecli_image", lambda *_args: "SBOM ID - project-42")
    monkeypatch.setattr(scan, "poll_job", lambda *_args: job)
    vuln_data: dict[str, object] = {"total_hits": total_hits}
    if total_hits:
        vuln_data["function: stats count()"] = {
            "vulnerability_by_severity": {"buckets": [{"key": "Medium", "doc_count": 1}]}
        }
    monkeypatch.setattr(
        scan, "fetch_vulnerability_summary",
        lambda *_args: fetches.append(True) or vuln_data,
    )
    monkeypatch.setattr(scan.time, "sleep", waits.append)

    scan.main()

    output = capsys.readouterr().out
    assert ("::warning title=Lineaje scan may be incomplete::" in output) is expected_alert
    assert summary.exists() is (expected_alert or expected_notice)
    if expected_alert or expected_notice:
        expected_url = (
            f"https://app.veedna.com/{expected_company_id}/"
            f"SBOM360/projects/{TEST_SBOM_ID}/info"
        )
        assert expected_url in output
        assert expected_url in summary.read_text()
    if expected_notice:
        assert f"reported {component_count} unique components" in summary.read_text()
    if total_hits:
        assert "Medium:    1" in output
        assert scan.parse_vulnerability_summary(output) == {
            "Exploited": 0, "Critical": 0, "High": 0,
        }
    assert len(fetches) == (10 if total_hits == 0 else 1)
    assert waits == ([5] + [15] * 9 if total_hits == 0 else [5])


def test_poll_job_retries_request_errors_and_accepts_status_alias(monkeypatch):
    responses = [
        requests.ConnectionError("temporary outage"),
        FakeResponse({"result": {"jobStatus": "processing"}}),
        FakeResponse({"result": {"State": "Ready for Review"}}),
    ]
    sleeps = []

    def fake_get(*_args, **_kwargs):
        response = responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(scan.requests, "get", fake_get)
    monkeypatch.setattr(scan.time, "sleep", sleeps.append)

    result = scan.poll_job("https://scim.example", "token", "42", 3, 4)

    assert result["result"]["State"] == "Ready for Review"
    assert sleeps == [3, 3]


def test_poll_job_times_out(monkeypatch):
    monkeypatch.setattr(
        scan.requests,
        "get",
        lambda *_args, **_kwargs: FakeResponse({"status": "processing"}),
    )
    monkeypatch.setattr(scan.time, "sleep", lambda _seconds: None)

    with pytest.raises(SystemExit, match="Timed out after 2 attempts"):
        scan.poll_job("https://scim.example", "token", "42", 0, 2)


def test_apply_fix_left_plan_recovers_from_expired_guid(monkeypatch):
    replies = iter([
        {"guid": "first", "message": "Request is being processed", "task_ids": []},
        {"guid": None, "message": "Request is still processing", "task_ids": []},
        {"guid": None, "message": "Created tasks for AI Agents", "task_ids": ["task-1"]},
    ])
    calls = []

    def fake_post(*_args, **kwargs):
        calls.append(kwargs)
        return next(replies)

    monkeypatch.setattr(scan, "_post_explain", fake_post)
    monkeypatch.setattr(scan.time, "sleep", lambda _seconds: None)

    result = scan.apply_fix_left_plan(
        "https://gpt.example", "token", "sbom", [{"suggested_purl": "pkg:npm/a@2"}],
        poll_interval=0, max_attempts=3,
    )

    assert result["task_ids"] == ["task-1"]
    assert [call.get("guid") for call in calls] == [None, "first", None]
    assert all(call["metadata"]["components"] for call in calls)


def test_apply_fix_left_plan_accepts_explicit_no_task_completion(monkeypatch):
    monkeypatch.setattr(
        scan,
        "_post_explain",
        lambda *_args, **_kwargs: {
            "guid": None,
            "message": "Completed processing",
            "task_ids": [],
        },
    )

    result = scan.apply_fix_left_plan(
        "https://gpt.example", "token", "sbom", [], poll_interval=0, max_attempts=0,
    )

    assert result["task_ids"] == []


def test_poll_fix_plan_renews_expired_guid(monkeypatch):
    replies = iter([
        {"guid": None, "message": "still working", "meta_data": {}},
        {
            "guid": None,
            "message": "done",
            "meta_data": {"overall_status": "available", "plan_details": []},
        },
    ])
    guids = []

    def fake_post(*_args, **kwargs):
        guids.append(kwargs.get("guid"))
        return next(replies)

    monkeypatch.setattr(scan, "_post_explain", fake_post)
    monkeypatch.setattr(scan.time, "sleep", lambda _seconds: None)

    result = scan.poll_fix_plan(
        "https://gpt.example", "token", "sbom", "expired", poll_interval=0, max_attempts=2,
    )

    assert result["meta_data"]["overall_status"] == "available"
    assert guids == ["expired", None]


def test_render_template_rejects_leftover_placeholders(tmp_path, monkeypatch):
    (tmp_path / "broken.txt").write_text("value=__MISSING__\n")
    monkeypatch.setattr(scan, "TEMPLATES_DIR", tmp_path)

    with pytest.raises(RuntimeError, match="__MISSING__"):
        scan._render_template("broken.txt")


def test_normalize_pip_index_urls_encodes_credentials():
    value = "https://user@example.com:p/a%25ss@example.invalid/simple https://pypi.org/simple"

    assert scan._normalize_pip_index_urls(value) == (
        "https://user%40example.com:p%2Fa%25ss@example.invalid/simple https://pypi.org/simple"
    )


@pytest.mark.parametrize(
    "plan",
    [
        {"suggested_purl": "pkg:npm/helmet@2.3.0-lineaje-01"},
        {"suggested_purl": "pkg:pypi/flask@0.12.5+lineaje.1"},
        {"suggested_purl": "pkg:pypi/flask@0.12.5%2Blineaje.1"},
        {"type": "premium", "suggested_purl": "pkg:pypi/flask@0.12.5"},
        {"status": "request premium package", "suggested_purl": "pkg:pypi/flask@0.12.5"},
    ],
)
def test_is_fortknox_only_fix_recognizes_metadata_and_ecosystem_suffixes(plan):
    assert scan._is_fortknox_only_fix(plan)


def test_is_fortknox_only_fix_keeps_curated_candidate():
    assert not scan._is_fortknox_only_fix(
        {"type": "curated", "status": "available", "suggested_purl": "pkg:pypi/requests@2.34.2"}
    )


def test_write_fix_config_protects_registry_files(tmp_path, monkeypatch):
    veecli_dir = tmp_path / "veecli-bin"
    veecli_dir.mkdir()
    veecli = veecli_dir / "veecli"
    veecli.write_text("")
    home_config = tmp_path / "home" / "veecli" / "config.json"
    monkeypatch.setattr(scan, "DEFAULT_CONFIG", home_config)
    monkeypatch.delenv("PIP_EXTRA_INDEX_URL", raising=False)

    result = scan.write_fix_config(
        str(veecli), token="secret-token", gos_mode="observe",
        language="node", language_version="20", timeout_seconds=17,
    )

    assert result == veecli_dir / "fix.yml"
    for name in (
        scan.VERIFY_NPMRC_NAME,
        scan.VERIFY_SETTINGS_XML_NAME,
        scan.VERIFY_NUGET_CONFIG_NAME,
        scan.VERIFY_INIT_GRADLE_NAME,
    ):
        path = veecli_dir / name
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert "secret-token" not in path.read_text()
    for directory in (veecli_dir, home_config.parent):
        assert (directory / "fix.yml").is_file()
        assert (directory / "fix.yaml").is_file()


def test_write_fix_config_passes_python_repo_root_to_verifier(tmp_path, monkeypatch):
    veecli_dir = tmp_path / "veecli-bin"
    veecli_dir.mkdir()
    veecli = veecli_dir / "veecli"
    veecli.write_text("")
    monkeypatch.setattr(scan, "DEFAULT_CONFIG", tmp_path / "home" / "veecli" / "config.json")
    monkeypatch.delenv("PIP_EXTRA_INDEX_URL", raising=False)
    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    scan.write_fix_config(
        str(veecli), token="", gos_mode="observe", language="python",
        language_version="3.12", repo_root=str(repo_root),
    )

    assert str(repo_root.resolve()) in (veecli_dir / "fix.yml").read_text()


def test_write_fix_config_skips_fortknox_files_when_disabled(tmp_path, monkeypatch):
    veecli_dir = tmp_path / "veecli-bin"
    veecli_dir.mkdir()
    veecli = veecli_dir / "veecli"
    veecli.write_text("")
    monkeypatch.setattr(scan, "DEFAULT_CONFIG", tmp_path / "home" / "veecli" / "config.json")
    monkeypatch.delenv("PIP_EXTRA_INDEX_URL", raising=False)

    scan.write_fix_config(
        str(veecli), token="secret-token", language="node", language_version="20",
        connect_to_fortknox=False,
    )

    for name in (
        scan.VERIFY_NPMRC_NAME,
        scan.VERIFY_SETTINGS_XML_NAME,
        scan.VERIFY_NUGET_CONFIG_NAME,
        scan.VERIFY_INIT_GRADLE_NAME,
    ):
        assert not (veecli_dir / name).exists()
    assert '- "--connect-to-fortknox"\n          - "false"' in (veecli_dir / "fix.yml").read_text()


@pytest.mark.parametrize(("no_connect", "expected"), [(True, False), (False, True)])
def test_main_forwards_fortknox_flag_to_fix_plan(tmp_path, monkeypatch, no_connect, expected):
    veecli_dir = tmp_path / "veecli"
    veecli_dir.mkdir()
    config = tmp_path / "config.json"
    arguments = [
        "lineaje_scan_gh.py", "--name", "project", "--version", "1",
        "--org-name", "org", "--refresh-token", "token",
        "--config-orig", str(tmp_path / "config-orig.json"), "--config", str(config),
        "--veecli", str(veecli_dir / "veecli"), "--output-dir", str(tmp_path / "out"),
        "--src-folder", str(tmp_path), "--src-url", "https://example.com/repo",
        "--matching-ref", "main", "--company-id", "tenant", "--language", "dotnet",
        "--language-version", "8.0", "--gos-fix-plan",
    ]
    if no_connect:
        arguments.append("--no-connect-to-fortknox")
    settings = []
    monkeypatch.setattr(sys, "argv", arguments)
    monkeypatch.setattr(
        scan, "build_config", lambda _orig, _refresh, path, _overrides: Path(path).write_text("{}")
    )
    monkeypatch.setattr(scan, "get_auth_token", lambda _cfg: "access-token")
    monkeypatch.setattr(scan, "validate_org_matches_token", lambda *_args: None)
    monkeypatch.setattr(scan, "get_scim_host", lambda _cfg: "https://scim.example")
    monkeypatch.setattr(scan, "get_data_host", lambda *_args: "https://data.example")
    monkeypatch.setattr(scan, "get_gpt_host", lambda *_args: "https://gpt.example")
    monkeypatch.setattr(scan, "write_input_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(scan, "run_veecli_source", lambda *_args: "SBOM ID - project-42")
    monkeypatch.setattr(
        scan, "poll_job",
        lambda *_args: {"result": {"job_status": "Ready for review", "sbom_id": "test-sbom"}},
    )
    monkeypatch.setattr(scan, "fetch_vulnerability_summary", lambda *_args: {"total_hits": 1})
    monkeypatch.setattr(scan.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        scan, "_run_fix_plan", lambda *_args, **kwargs: settings.append(kwargs["connect_to_fortknox"])
    )

    scan.main()

    assert settings == [expected]


@pytest.mark.parametrize(
    ("language", "connect_to_fortknox", "premium_plan", "keeps_premium"),
    [
        ("golang", True, {"suggested_purl": "pkg:npm/premium@2-lineaje-01"}, False),
        ("node", False, {"suggested_purl": "pkg:npm/premium@2-lineaje-01"}, False),
        ("node", True, {"suggested_purl": "pkg:npm/premium@2-lineaje-01"}, True),
        (
            "python",
            False,
            {
                "type": "premium",
                "status": "request premium package",
                "suggested_purl": "pkg:pypi/flask@0.12.5+lineaje.1",
            },
            False,
        ),
        (
            "python",
            True,
            {"type": "premium", "suggested_purl": "pkg:pypi/flask@0.12.5+lineaje.1"},
            True,
        ),
    ],
)
def test_run_fix_plan_respects_fortknox_setting(
    tmp_path, monkeypatch, language, connect_to_fortknox, premium_plan, keeps_premium
):
    fix_data = {
        "meta_data": {
            "overall_status": "available",
            "plan_details": [
                {"suggested_purl": "pkg:npm/public@2", "vuln_fixed": ["CVE-1"]},
                {**premium_plan, "vuln_fixed": ["CVE-2"]},
            ],
        }
    }
    submitted = []
    veecli_runs = []
    config_settings = []
    monkeypatch.setattr(scan, "request_gos_plan", lambda *_args: (None, {}))
    monkeypatch.setattr(scan, "request_fix_plan", lambda *_args: (None, copy.deepcopy(fix_data)))
    monkeypatch.setattr(scan, "write_raw_fix_plan", lambda *_args, **_kwargs: tmp_path / "raw.json")
    monkeypatch.setattr(scan, "print_fix_plan", lambda *_args: None)
    monkeypatch.setattr(
        scan, "write_fix_config",
        lambda *_args, **kwargs: config_settings.append(kwargs["connect_to_fortknox"]) or tmp_path / "fix.yml",
    )
    monkeypatch.setattr(
        scan,
        "apply_fix_left_plan",
        lambda _host, _token, _sbom, plans, **_kwargs: submitted.extend(plans) or {"task_ids": ["1"]},
    )
    monkeypatch.setattr(scan, "run_veecli_fix", lambda *_args: veecli_runs.append(True))
    monkeypatch.setattr(scan, "_print_fix_dir", lambda *_args: None)

    result = scan._run_fix_plan(
        "https://gpt.example", "token", "sbom", str(tmp_path), 0, 1,
        gos=True, veecli="veecli", src_folder="src", output_fix_dir="fix",
        cli_token="token", language=language,
        connect_to_fortknox=connect_to_fortknox,
    )

    expected = ["pkg:npm/public@2"]
    if keeps_premium:
        expected.append(premium_plan["suggested_purl"])
    assert [plan["suggested_purl"] for plan in submitted] == expected
    assert result["meta_data"]["plan_details"] == submitted
    assert veecli_runs == [True]
    assert config_settings == [connect_to_fortknox]