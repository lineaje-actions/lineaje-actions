import copy
import stat
from pathlib import Path

import pytest
import requests

import lineaje_scan_gh as scan


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


@pytest.mark.parametrize(
    ("language", "connect_to_fortknox"),
    [("golang", True), ("node", False)],
)
def test_run_fix_plan_filters_fortknox_only_candidates(
    tmp_path, monkeypatch, language, connect_to_fortknox
):
    fix_data = {
        "meta_data": {
            "overall_status": "available",
            "plan_details": [
                {"suggested_purl": "pkg:npm/public@2", "vuln_fixed": ["CVE-1"]},
                {"suggested_purl": "pkg:npm/premium@2-lineaje-01", "vuln_fixed": ["CVE-2"]},
            ],
        }
    }
    submitted = []
    veecli_runs = []
    monkeypatch.setattr(scan, "request_gos_plan", lambda *_args: (None, {}))
    monkeypatch.setattr(scan, "request_fix_plan", lambda *_args: (None, copy.deepcopy(fix_data)))
    monkeypatch.setattr(scan, "write_raw_fix_plan", lambda *_args, **_kwargs: tmp_path / "raw.json")
    monkeypatch.setattr(scan, "print_fix_plan", lambda *_args: None)
    monkeypatch.setattr(scan, "write_fix_config", lambda *_args, **_kwargs: tmp_path / "fix.yml")
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

    assert [plan["suggested_purl"] for plan in submitted] == ["pkg:npm/public@2"]
    assert result["meta_data"]["plan_details"] == submitted
    assert veecli_runs == [True]