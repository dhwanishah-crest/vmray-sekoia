"""Submit Sample: upload files of the playbook run's storage to VMRay and return at once."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from sekoia_automation.action import Action

from tests.submit_mocks import OTHER, SHA1, make, mock_submission, mock_submit
from vmray_modules.submission_models import SubmitSampleArguments, SubmitSampleResults
from vmray_modules.submit_sample_action import SubmitSample

ROOT = Path(__file__).parents[1]


def test_submit_sample_uploads_and_returns_without_polling(requests_mock, storage_file):
    storage_file(SHA1)
    submit = mock_submit(requests_mock, 111)
    poll = mock_submission(requests_mock, 111, finished=False)
    action = make(SubmitSample)

    result = action.run({"files": [{"path": SHA1}]})  # as SentinelOne's Get malwares from threat returns it

    assert result["submitted"] is True
    assert result["submission_ids"] == [111]
    assert result["submitted_files"] == [SHA1]
    assert result["errors"] == []
    assert submit.call_count == 1
    assert poll.call_count == 0  # nothing asks VMRay whether it finished
    assert action.outputs == {"submitted": True}


def test_submit_sample_returns_at_once_even_when_the_analysis_runs_for_a_long_time(requests_mock, storage_file):
    storage_file(SHA1)
    mock_submit(requests_mock, 111)
    mock_submission(requests_mock, 111, finished=False)

    result = make(SubmitSample).run({"files": [SHA1], "timeout": 1})  # an input the action does not have is ignored

    assert result["submission_ids"] == [111]


def test_submit_sample_submits_each_file_and_keeps_going_after_a_bad_one(requests_mock, storage_file):
    storage_file(SHA1)
    storage_file(OTHER, b"")
    mock_submit(requests_mock, 111)
    action = make(SubmitSample)

    result = action.run({"files": [SHA1, OTHER, "missing"]})

    assert result["submission_ids"] == [111]
    assert result["submitted_files"] == [SHA1]
    assert {e["file"]: e["error_msg"] for e in result["errors"]} == {
        OTHER: "the file is empty",
        "missing": "no such file in the playbook run's data storage",
    }
    assert action.outputs == {"submitted": True}


def test_submit_sample_with_nothing_accepted_takes_the_failed_branch(requests_mock, storage_file):
    storage_file(SHA1)
    mock_submit(requests_mock, errors=[{"error_msg": "no quota left"}])
    action = make(SubmitSample)

    result = action.run({"files": [SHA1]})

    assert result["submitted"] is False
    assert result["submission_ids"] == []
    assert result["errors"] == [{"file": SHA1, "error_msg": "no quota left"}]
    assert action.outputs == {"submission_failed": True}


def test_submit_sample_rejects_a_path_outside_the_storage(requests_mock):
    mock_submit(requests_mock, 111)
    action = make(SubmitSample)

    result = action.run({"files": ["../secret", "/etc/passwd"]})

    assert result["submitted"] is False
    assert {e["error_msg"] for e in result["errors"]} == {"not a path inside the playbook run's data storage"}
    assert requests_mock.call_count == 0


def test_submit_sample_needs_at_least_one_file():
    with pytest.raises(ValidationError):
        SubmitSampleArguments(files=[])


def test_submit_sample_sends_the_options_and_cleaned_tags(requests_mock, storage_file):
    storage_file(SHA1)
    submit = mock_submit(requests_mock, 111)

    make(SubmitSample).run(
        {"files": [SHA1], "tags": ["", " alert-1 ", "sekoia"], "reanalyze": False, "shareable": True}
    )

    body = submit.last_request.body  # multipart: the file and the form fields
    assert b'name="tags"' in body and b"alert-1,sekoia" in body
    assert b'name="reanalyze"' not in body  # false is left out: VMRay's own default applies
    assert b'name="shareable"' in body


def test_the_manifest_matches_the_models():
    manifest = json.loads((ROOT / "action_submit_sample.json").read_text(encoding="utf-8"))

    assert issubclass(SubmitSample, Action)
    assert manifest["docker_parameters"] == "SubmitSample"
    assert manifest["name"] == SubmitSample.name
    assert manifest["arguments"] == SubmitSampleArguments.model_json_schema()
    assert manifest["results"] == SubmitSampleResults.model_json_schema()
