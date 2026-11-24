"""Get Submission Result: one look at whether submissions have finished."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from sekoia_automation.action import Action

from tests.submit_mocks import BASE_URL, SHA1, make, mock_submission, mock_submit, ok
from vmray_modules.get_submission_result_action import GetSubmissionResult
from vmray_modules.submission_models import GetSubmissionResultArguments, GetSubmissionResultResults
from vmray_modules.submit_sample_action import SubmitSample

ROOT = Path(__file__).parents[1]


def test_get_submission_result_completed_when_every_submission_finished(requests_mock):
    mock_submission(requests_mock, 111, sample_id=5, submission_verdict="malicious")
    mock_submission(requests_mock, 112, sample_id=5)
    mock_submission(requests_mock, 113, sample_id=6)
    action = make(GetSubmissionResult)

    result = action.run({"submission_ids": [111, 112, 113]})

    assert result["all_finished"] is True
    assert result["submission_ids"] == [111, 112, 113]
    assert result["sample_ids"] == [5, 6]  # a sample shared by two submissions once
    assert result["pending_submission_ids"] == [] and result["failed_submission_ids"] == []
    assert result["submissions"][0]["submission_verdict"] == "malicious"
    assert action.outputs == {"completed": True}


def test_get_submission_result_pending_while_a_submission_still_runs_and_keeps_what_finished(requests_mock):
    mock_submission(requests_mock, 111, sample_id=5)
    mock_submission(requests_mock, 112, finished=False)
    action = make(GetSubmissionResult)

    result = action.run({"submission_ids": [111, 112]})

    assert result["all_finished"] is False
    assert result["pending_submission_ids"] == [112]
    assert result["submission_ids"] == [111] and result["sample_ids"] == [5]
    assert action.outputs == {"pending": True}


def test_get_submission_result_makes_one_poll_per_submission_and_never_waits(requests_mock):
    poll = mock_submission(requests_mock, 111, finished=False)

    make(GetSubmissionResult).run({"submission_ids": [111]})

    assert poll.call_count == 1


def test_get_submission_result_failed_when_every_submission_finished_with_an_error(requests_mock):
    mock_submission(requests_mock, 111, has_errors=True)
    mock_submission(requests_mock, 112, has_errors=True)
    action = make(GetSubmissionResult)

    result = action.run({"submission_ids": [111, 112]})

    assert result["all_finished"] is True
    assert result["failed_submission_ids"] == [111, 112]
    assert result["submission_ids"] == []
    assert [e["submission_id"] for e in result["errors"]] == [111, 112]
    assert action.outputs == {"failed": True}


def test_get_submission_result_completed_when_some_failed_and_the_rest_finished(requests_mock):
    mock_submission(requests_mock, 111, sample_id=5)
    mock_submission(requests_mock, 112, has_errors=True)
    action = make(GetSubmissionResult)

    result = action.run({"submission_ids": [111, 112]})

    assert result["submission_ids"] == [111] and result["failed_submission_ids"] == [112]
    assert action.outputs == {"completed": True}


def test_get_submission_result_a_submission_that_cannot_be_checked_stays_pending_with_the_reason(requests_mock):
    mock_submission(requests_mock, 111, sample_id=5)
    requests_mock.get(f"{BASE_URL}/rest/submission/112", status_code=404, json={"error_msg": "no such submission"})
    action = make(GetSubmissionResult)

    result = action.run({"submission_ids": [111, 112]})

    assert result["pending_submission_ids"] == [112]
    assert result["failed_submission_ids"] == []  # not failed: the next check may well work
    assert "could not be checked" in result["errors"][0]["error_msg"]
    assert "no such submission" in result["errors"][0]["error_msg"]
    assert action.outputs == {"pending": True}


def test_get_submission_result_fails_when_not_one_submission_could_be_checked(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/submission/111", status_code=401, json={"error_msg": "bad key"})
    requests_mock.get(f"{BASE_URL}/rest/submission/112", status_code=401, json={"error_msg": "bad key"})

    with pytest.raises(Exception, match=r"No submission could be checked.*bad key"):
        make(GetSubmissionResult).run({"submission_ids": [111, 112]})


def test_get_submission_result_an_answer_that_is_not_a_submission_is_unchecked_not_failed(requests_mock):
    mock_submission(requests_mock, 111, sample_id=5)
    requests_mock.get(f"{BASE_URL}/rest/submission/112", json=ok({"unexpected": True}))

    result = make(GetSubmissionResult).run({"submission_ids": [111, 112]})

    assert result["pending_submission_ids"] == [112]


def test_get_submission_result_takes_one_id_or_a_list_and_checks_duplicates_once(requests_mock):
    poll = mock_submission(requests_mock, 111, sample_id=5)

    assert make(GetSubmissionResult).run({"submission_ids": 111})["submission_ids"] == [111]
    assert make(GetSubmissionResult).run({"submission_ids": [111, 111]})["submission_ids"] == [111]
    assert poll.call_count == 2  # one poll per call


@pytest.mark.parametrize(
    ("given", "checked"),
    [(111, [111]), ([111, 111, 112], [111, 112]), (["111", 111], [111]), ([1, 1.0], [1]), ([-5], [-5])],
)
def test_get_submission_result_input_is_made_of_distinct_integers(given, checked):
    assert GetSubmissionResultArguments(submission_ids=given).submission_ids == checked


@pytest.mark.parametrize("given", ["111", "1,2", True, 1.5, [1.5], [None], [[1]], [{"a": 1}], None, []])
def test_get_submission_result_refuses_what_is_not_a_list_of_ids(given):
    with pytest.raises(ValidationError):
        GetSubmissionResultArguments(submission_ids=given)


def test_get_submission_result_needs_at_least_one_submission_id():
    with pytest.raises(ValidationError):
        GetSubmissionResultArguments(submission_ids=[])


def test_get_submission_result_takes_what_submit_sample_returns(requests_mock, storage_file):
    """The chain a playbook builds: Submit Sample, later Get Submission Result, then Build Report."""
    storage_file(SHA1)
    mock_submit(requests_mock, 111)
    started = make(SubmitSample).run({"files": [SHA1]})
    mock_submission(requests_mock, 111, finished=False)

    first = make(GetSubmissionResult).run({"submission_ids": started["submission_ids"]})
    mock_submission(requests_mock, 111, sample_id=222)
    second = make(GetSubmissionResult).run({"submission_ids": started["submission_ids"]})

    assert first["pending_submission_ids"] == [111]
    assert second["submission_ids"] == [111] and second["sample_ids"] == [222]  # input for Build Report


def test_the_manifest_matches_the_models():
    manifest = json.loads((ROOT / "action_get_submission_result.json").read_text(encoding="utf-8"))

    assert issubclass(GetSubmissionResult, Action)
    assert manifest["docker_parameters"] == "GetSubmissionResult"
    assert manifest["name"] == GetSubmissionResult.name
    assert manifest["arguments"] == GetSubmissionResultArguments.model_json_schema()
    assert manifest["results"] == GetSubmissionResultResults.model_json_schema()
