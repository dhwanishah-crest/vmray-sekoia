import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from vmray_modules.models import VMRayConfiguration, VMRayModule
from vmray_modules.submission_models import SubmitSampleAndWaitArguments, SubmitSampleAndWaitResults
from vmray_modules.submit_sample_and_wait_action import SubmitSampleAndWait

BASE_URL = "https://eu.cloud.vmray.com"
SHA1 = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
OTHER = "b94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
MANIFEST = Path(__file__).parents[1] / "action_submit_sample_and_wait.json"


def make_action():
    m = VMRayModule()
    m.configuration = VMRayConfiguration(base_url=BASE_URL, api_key="test-key")
    return SubmitSampleAndWait(module=m)


def ok(data):
    return {"result": "ok", "data": data}


def submitted(*submission_ids, errors=()):
    return {"json": ok({"submissions": [{"submission_id": i} for i in submission_ids], "errors": list(errors)})}


def finished(submission_id, sample_id, **extra):
    return {
        "json": ok(
            {"submission_id": submission_id, "submission_finished": True, "submission_sample_id": sample_id, **extra}
        )
    }


def running(submission_id):
    return {"json": ok({"submission_id": submission_id, "submission_finished": False})}


@pytest.fixture
def storage(data_storage):
    def write(name, content=b"MZ\x90\x00malware"):
        (Path(data_storage) / name).write_bytes(content)
        return name

    return write


def uploaded(request):
    """The multipart body of a POST /sample/submit, as {field: value} plus the uploaded file's (name, bytes)."""
    body = request.body
    boundary = request.headers["Content-Type"].split("boundary=")[1].encode()
    fields, upload = {}, None
    for part in body.split(b"--" + boundary)[1:-1]:
        head, _, value = part.strip(b"\r\n").partition(b"\r\n\r\n")
        name = head.split(b'name="')[1].split(b'"')[0].decode()
        if b"filename=" in head:
            upload = (head.split(b'filename="')[1].split(b'"')[0].decode(), value)
        else:
            fields[name] = value.decode()
    return fields, upload


def test_uploads_the_sentinelone_file_and_waits_until_it_finishes(requests_mock, storage):
    storage(SHA1)
    submit = requests_mock.post(f"{BASE_URL}/rest/sample/submit", [submitted(111)])
    requests_mock.get(
        f"{BASE_URL}/rest/submission/111", [running(111), finished(111, 222, submission_verdict="malicious")]
    )
    action = make_action()

    # passed exactly as SentinelOne's Get malwares from threat returns it
    result = action.run({"files": [{"path": SHA1}], "query_retry_wait": 0.01, "analyzer_mode": "static_dynamic"})

    fields, upload = uploaded(submit.last_request)
    assert upload == (SHA1, b"MZ\x90\x00malware")
    assert fields == {
        "reanalyze": "True",
        "tags": "sekoia",
        "analyzer_mode": "static_dynamic",
        "shareable": "False",
        "max_recursive_samples": "10",
    }
    assert "sample_url" not in fields
    assert result["submitted_files"] == [SHA1]
    assert result["submission_ids"] == [111]
    assert result["sample_ids"] == [222]
    assert result["submissions"][0]["submission_verdict"] == "malicious"
    assert action.outputs == {"completed": True}


def test_every_file_is_submitted_and_every_submission_followed(requests_mock, storage):
    storage(SHA1)
    storage(OTHER, b"second")
    submit = requests_mock.post(f"{BASE_URL}/rest/sample/submit", [submitted(111), submitted(112)])
    requests_mock.get(f"{BASE_URL}/rest/submission/111", [finished(111, 222)])
    requests_mock.get(f"{BASE_URL}/rest/submission/112", [running(112), finished(112, 223)])

    result = make_action().run({"files": [{"path": SHA1}, {"path": OTHER}, {"path": SHA1}], "query_retry_wait": 0.01})

    assert submit.call_count == 2  # the duplicate is submitted (and billed) once
    assert result["submitted_files"] == [SHA1, OTHER]
    assert result["submission_ids"] == [111, 112]
    assert result["sample_ids"] == [222, 223]


def test_one_unreadable_or_refused_file_does_not_stop_the_others(requests_mock, storage):
    storage(SHA1)
    storage(OTHER)
    storage("empty", b"")
    requests_mock.post(
        f"{BASE_URL}/rest/sample/submit",
        [{"status_code": 403, "json": {"result": "error", "error_msg": "Quota exceeded"}}, submitted(112)],
    )
    requests_mock.get(f"{BASE_URL}/rest/submission/112", [finished(112, 223)])
    action = make_action()

    result = action.run({"files": [SHA1, "missing", "../etc/passwd", "empty", OTHER], "query_retry_wait": 0.01})

    assert result["submitted_files"] == [OTHER]
    assert result["sample_ids"] == [223]
    assert {e["file"]: e["error_msg"] for e in result["errors"]} == {
        SHA1: "VMRay API request failed (HTTP 403): Quota exceeded",
        "missing": "no such file in the playbook run's data storage",
        "../etc/passwd": "not a path inside the playbook run's data storage",
        "empty": "the file is empty",
    }
    assert action.outputs == {"completed": True}


def test_nothing_submitted_takes_the_submission_failed_branch(requests_mock, storage):
    storage(SHA1)
    requests_mock.post(f"{BASE_URL}/rest/sample/submit", [submitted(errors=[{"error_msg": "Unsupported file"}])])
    action = make_action()

    result = action.run({"files": [SHA1, "missing"]})

    assert action.outputs == {"submission_failed": True}
    assert result["submission_ids"] == []
    assert result["errors"] == [
        {"file": SHA1, "error_msg": "Unsupported file"},
        {"file": "missing", "error_msg": "no such file in the playbook run's data storage"},
    ]


def test_timeout_takes_the_timed_out_branch(requests_mock, storage):
    storage(SHA1)
    requests_mock.post(f"{BASE_URL}/rest/sample/submit", [submitted(111)])
    requests_mock.get(f"{BASE_URL}/rest/submission/111", [running(111)])
    action = make_action()

    result = action.run({"files": [SHA1], "query_retry_wait": 0.01, "timeout": 0.05})

    assert action.outputs == {"timed_out": True}
    assert result["pending_submission_ids"] == [111]
    assert result["submitted_files"] == [SHA1]


@pytest.mark.parametrize(
    ("given", "paths"),
    [
        ([{"path": SHA1}], [SHA1]),
        ({"path": SHA1}, [SHA1]),
        (SHA1, [SHA1]),
        ([f" {SHA1} ", SHA1, ""], [SHA1]),
    ],
)
def test_files_input_takes_the_sentinelone_output_as_is(given, paths):
    assert SubmitSampleAndWaitArguments(files=given).files == paths


@pytest.mark.parametrize("given", [[], [""], [{"name": "x"}], [42]])
def test_files_input_refuses_no_file(given):
    with pytest.raises(ValidationError):
        SubmitSampleAndWaitArguments(files=given)


def test_manifest_matches_the_models():
    manifest = json.loads(MANIFEST.read_text())

    assert manifest["docker_parameters"] == "SubmitSampleAndWait"
    assert manifest["arguments"] == SubmitSampleAndWaitArguments.model_json_schema()
    assert manifest["results"] == SubmitSampleAndWaitResults.model_json_schema()
