"""Runs the SentinelOne malware → VMRay sandbox playbook (playbooks/templates/new.json) end to end on the engine of
test_playbook_template: the VMRay actions run for real against the fake VMRay; SentinelOne's Get malwares from
threat is emulated the way it behaves — it writes the fetched file(s) to the playbook run's data storage, named by
SHA-1, and returns their paths."""

import hashlib
import json
from pathlib import Path

import pytest

from tests.test_integration import BASE_URL, URL, FakeVMRay, ok, sekoia  # noqa: F401
from tests.test_playbook_template import playbook, pushed, screenshot_comments  # noqa: F401

TEMPLATE = Path(__file__).parent / "data" / "new.json"
PUBLISHED_TEMPLATE = Path(__file__).resolve().parents[2] / "playbooks" / "templates" / "new.json"
THREAT_ID = "1712345678901234567"
MALWARE = b"MZ\x90\x00\x03 not really malware"
TENANT_KEYS = {"trigger_configuration_uuid", "module_configuration_uuid", "community_uuid"}


@pytest.fixture
def sentinelone(sekoia):  # noqa: F811
    """Get malwares from threat: records each call; `fetch` sets what the endpoint gives back."""
    calls = []
    state = {"files": [MALWARE], "status": "succeed", "reason": "The malware was successfully retrieved"}

    def get_malwares(arguments):
        calls.append(arguments)
        paths = []
        for content in state["files"]:
            name = hashlib.sha1(content).hexdigest()
            (sekoia.data_path / name).write_bytes(content)
            paths.append({"path": name})
        if state["status"] != "succeed":
            paths = []
        return {"status": state["status"], "status_reason": state["reason"], "files": paths}

    get_malwares.calls = calls
    get_malwares.state = state
    return get_malwares


@pytest.fixture
def run_playbook(playbook, sentinelone):  # noqa: F811
    def run(events, **overrides):
        return playbook(events, template=TEMPLATE, sentinelone=sentinelone, **overrides)

    return run


def s1_event(**extra):
    return {"sentinelone.threatId": THREAT_ID, **extra}


def uploads(requests_mock):
    return [r for r in requests_mock.request_history if r.method == "POST" and r.url.endswith("/rest/sample/submit")]


@pytest.mark.skipif(not PUBLISHED_TEMPLATE.exists(), reason="the published playbook templates are not alongside")
def test_template_copy_matches_the_published_template():
    assert json.loads(TEMPLATE.read_text()) == json.loads(PUBLISHED_TEMPLATE.read_text())


def test_template_carries_no_tenant_identifier():
    for node_id, node in json.loads(TEMPLATE.read_text())["nodes"].items():
        assert not TENANT_KEYS & set(node), node_id


def test_malware_is_fetched_sandboxed_reported_and_its_iocs_pushed(run_playbook, sentinelone, requests_mock):
    FakeVMRay(requests_mock)

    run = run_playbook([s1_event()])

    assert not run.failures
    assert sentinelone.calls == [{"timeout": 300, "threat_id": THREAT_ID}]
    [upload] = uploads(requests_mock)
    assert MALWARE in upload.body and b'name="sample_file"' in upload.body
    assert hashlib.sha1(MALWARE).hexdigest().encode() in upload.body  # sent under SentinelOne's file name
    assert run.results[6]["submission_ids"] == [111]
    assert not run.ran("7") and not run.ran("9")
    [report] = [c for c in run.comments if "<img" not in c]
    assert "MALICIOUS" in report and "Not in this report" not in report
    assert sum(c.count("<img") for c in screenshot_comments(run)) == 2
    assert ("domain", "login-check.example") in pushed(run)
    assert len(run.ioc_pushes) == len({t for t, _ in run.ioc_pushes})  # one push per indicator type


def test_every_fetched_file_is_submitted(run_playbook, sentinelone, requests_mock):
    FakeVMRay(requests_mock)
    sentinelone.state["files"] = [MALWARE, b"dropper"]

    run = run_playbook([s1_event()])

    assert not run.failures
    assert len(uploads(requests_mock)) == 2
    assert len(run.results[6]["submitted_files"]) == 2


@pytest.mark.parametrize("events", [[], [{"url.original": URL}], [{"sentinelone.threatId": ""}]])
def test_alert_without_sentinelone_threat_stops_silently(run_playbook, sentinelone, requests_mock, events):
    FakeVMRay(requests_mock)

    run = run_playbook(events)

    assert not run.failures
    assert not run.ran("4") and sentinelone.calls == []
    assert run.comments == [] and uploads(requests_mock) == []


def test_malware_not_retrieved_is_explained_without_spending_quota(run_playbook, sentinelone, requests_mock):
    FakeVMRay(requests_mock)
    sentinelone.state.update(status="timeout", reason="The agent did not upload the file in time")

    run = run_playbook([s1_event()])

    assert not run.failures
    assert run.ran("7") and not run.ran("6")
    assert uploads(requests_mock) == []
    [comment] = run.comments
    assert "no sample to analyse" in comment and THREAT_ID in comment
    assert "`timeout` — The agent did not upload the file in time." in comment


def test_sandbox_timeout_is_explained(run_playbook, requests_mock):
    FakeVMRay(requests_mock)
    requests_mock.get(f"{BASE_URL}/rest/submission/111", json=ok({"submission_id": 111, "submission_finished": False}))

    run = run_playbook([s1_event()])

    assert not run.failures
    assert run.ran("9") and not run.ran("8")
    assert "sandbox analysis incomplete" in run.comments[0]
    assert "submission(s) 111 may still finish" in run.comments[0]


def test_file_refused_by_vmray_is_explained(run_playbook, requests_mock):
    FakeVMRay(requests_mock)
    requests_mock.post(
        f"{BASE_URL}/rest/sample/submit", status_code=403, json={"result": "error", "error_msg": "Quota exceeded"}
    )

    run = run_playbook([s1_event()])

    assert not run.failures
    assert run.ran("9")
    sha1 = hashlib.sha1(MALWARE).hexdigest()
    assert f"- file `{sha1}`: `VMRay API request failed (HTTP 403): Quota exceeded`" in run.comments[0]
