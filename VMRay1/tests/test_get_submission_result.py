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

    result = action.run({"timeout": 0, "submission_ids": [111, 112, 113]})

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

    result = action.run({"timeout": 0, "submission_ids": [111, 112]})

    assert result["all_finished"] is False
    assert result["timed_out"] is False  # nothing was waited for
    assert result["pending_submission_ids"] == [112]
    assert result["submission_ids"] == [111] and result["sample_ids"] == [5]
    assert action.outputs == {"pending": True}


def test_get_submission_result_with_timeout_zero_checks_once_and_returns_at_once(requests_mock):
    poll = mock_submission(requests_mock, 111, finished=False)

    make(GetSubmissionResult).run({"timeout": 0, "submission_ids": [111]})

    assert poll.call_count == 1


def test_get_submission_result_failed_when_every_submission_finished_with_an_error(requests_mock):
    mock_submission(requests_mock, 111, has_errors=True)
    mock_submission(requests_mock, 112, has_errors=True)
    action = make(GetSubmissionResult)

    result = action.run({"timeout": 0, "submission_ids": [111, 112]})

    assert result["all_finished"] is True
    assert result["failed_submission_ids"] == [111, 112]
    assert result["submission_ids"] == []
    assert [e["submission_id"] for e in result["errors"]] == [111, 112]
    assert action.outputs == {"failed": True}


def test_get_submission_result_completed_when_some_failed_and_the_rest_finished(requests_mock):
    mock_submission(requests_mock, 111, sample_id=5)
    mock_submission(requests_mock, 112, has_errors=True)
    action = make(GetSubmissionResult)

    result = action.run({"timeout": 0, "submission_ids": [111, 112]})

    assert result["submission_ids"] == [111] and result["failed_submission_ids"] == [112]
    assert action.outputs == {"completed": True}


def test_get_submission_result_a_submission_that_cannot_be_checked_stays_pending_with_the_reason(requests_mock):
    mock_submission(requests_mock, 111, sample_id=5)
    requests_mock.get(f"{BASE_URL}/rest/submission/112", status_code=404, json={"error_msg": "no such submission"})
    action = make(GetSubmissionResult)

    result = action.run({"timeout": 0, "submission_ids": [111, 112]})

    assert result["pending_submission_ids"] == [112]
    assert result["failed_submission_ids"] == []  # not failed: the next check may well work
    assert "could not be checked" in result["errors"][0]["error_msg"]
    assert "no such submission" in result["errors"][0]["error_msg"]
    assert action.outputs == {"pending": True}


def test_get_submission_result_fails_when_not_one_submission_could_be_checked(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/submission/111", status_code=401, json={"error_msg": "bad key"})
    requests_mock.get(f"{BASE_URL}/rest/submission/112", status_code=401, json={"error_msg": "bad key"})

    with pytest.raises(Exception, match=r"No submission could be checked.*bad key"):
        make(GetSubmissionResult).run({"timeout": 0, "submission_ids": [111, 112]})


def test_get_submission_result_an_answer_that_is_not_a_submission_is_unchecked_not_failed(requests_mock):
    mock_submission(requests_mock, 111, sample_id=5)
    requests_mock.get(f"{BASE_URL}/rest/submission/112", json=ok({"unexpected": True}))

    result = make(GetSubmissionResult).run({"timeout": 0, "submission_ids": [111, 112]})

    assert result["pending_submission_ids"] == [112]


def test_get_submission_result_takes_one_id_or_a_list_and_checks_duplicates_once(requests_mock):
    poll = mock_submission(requests_mock, 111, sample_id=5)

    assert make(GetSubmissionResult).run({"timeout": 0, "submission_ids": 111})["submission_ids"] == [111]
    assert make(GetSubmissionResult).run({"timeout": 0, "submission_ids": [111, 111]})["submission_ids"] == [111]
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

    first = make(GetSubmissionResult).run({"timeout": 0, "submission_ids": started["submission_ids"]})
    mock_submission(requests_mock, 111, sample_id=222)
    second = make(GetSubmissionResult).run({"timeout": 0, "submission_ids": started["submission_ids"]})

    assert first["pending_submission_ids"] == [111]
    assert second["submission_ids"] == [111] and second["sample_ids"] == [222]  # input for Build Report


# ---- waiting -----------------------------------------------------------------------------------------------


def seq(*responses):
    """A GET /submission/{id} that answers with each of the given states in turn: "running", "done" or "error"."""
    out = []
    for r in responses:
        if r == "running":
            out.append({"json": ok({"submission_id": 111, "submission_finished": False})})
        elif r == "done":
            out.append({"json": ok({"submission_id": 111, "submission_finished": True, "submission_sample_id": 5})})
        elif r == "failed":
            out.append(
                {"json": ok({"submission_id": 111, "submission_finished": True, "submission_has_errors": True})}
            )
        else:
            out.append({"status_code": 404, "json": {"error_msg": "no such submission"}})
    return out


def test_get_submission_result_waits_until_the_submission_has_finished(requests_mock):
    poll = requests_mock.get(f"{BASE_URL}/rest/submission/111", seq("running", "running", "done"))
    action = make(GetSubmissionResult)

    result = action.run({"submission_ids": [111], "poll_interval": 0.01})

    assert poll.call_count == 3
    assert result["all_finished"] is True and result["timed_out"] is False
    assert result["submission_ids"] == [111] and result["sample_ids"] == [5]
    assert result["errors"] == []
    assert action.outputs == {"completed": True}


def test_get_submission_result_by_default_waits_without_a_timeout_of_its_own_choosing():
    arguments = GetSubmissionResultArguments(submission_ids=[1])

    assert arguments.timeout == 1800 and arguments.poll_interval == 10


def test_get_submission_result_takes_the_pending_branch_when_the_wait_times_out(requests_mock):
    poll = requests_mock.get(f"{BASE_URL}/rest/submission/111", seq("running"))
    action = make(GetSubmissionResult)

    result = action.run({"submission_ids": [111], "timeout": 0.05, "poll_interval": 0.01})

    assert poll.call_count >= 2  # it did poll more than once before giving up
    assert result["timed_out"] is True and result["all_finished"] is False
    assert result["pending_submission_ids"] == [111] and result["submission_ids"] == []
    assert action.outputs == {"pending": True}


def test_get_submission_result_asks_again_only_about_the_submissions_still_running(requests_mock):
    first = requests_mock.get(f"{BASE_URL}/rest/submission/111", seq("done"))
    second = requests_mock.get(
        f"{BASE_URL}/rest/submission/112",
        [
            {"json": ok({"submission_id": 112, "submission_finished": False})},
            {"json": ok({"submission_id": 112, "submission_finished": True, "submission_sample_id": 6})},
        ],
    )

    result = make(GetSubmissionResult).run({"submission_ids": [111, 112], "poll_interval": 0.01})

    assert first.call_count == 1 and second.call_count == 2
    assert result["submission_ids"] == [111, 112] and result["sample_ids"] == [5, 6]


def test_get_submission_result_a_failure_while_waiting_is_reported_and_the_rest_is_kept(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/submission/111", seq("failed"))
    requests_mock.get(
        f"{BASE_URL}/rest/submission/112",
        [
            {"json": ok({"submission_id": 112, "submission_finished": False})},
            {"json": ok({"submission_id": 112, "submission_finished": True, "submission_sample_id": 6})},
        ],
    )
    action = make(GetSubmissionResult)

    result = action.run({"submission_ids": [111, 112], "poll_interval": 0.01})

    assert result["failed_submission_ids"] == [111] and result["submission_ids"] == [112]
    assert [e["submission_id"] for e in result["errors"]] == [111]
    assert action.outputs == {"completed": True}


def test_get_submission_result_every_submission_failing_takes_the_failed_branch_without_waiting(requests_mock):
    poll = requests_mock.get(f"{BASE_URL}/rest/submission/111", seq("failed"))
    action = make(GetSubmissionResult)

    action.run({"submission_ids": [111], "poll_interval": 0.01})

    assert poll.call_count == 1
    assert action.outputs == {"failed": True}


def test_get_submission_result_a_check_that_fails_once_does_not_end_the_wait(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/submission/111", seq("error", "running", "done"))
    action = make(GetSubmissionResult)

    result = action.run({"submission_ids": [111], "poll_interval": 0.01})

    assert action.outputs == {"completed": True}
    assert result["errors"] == []  # the early failure is not kept once the submission was checked


def test_get_submission_result_keeps_the_reason_of_a_submission_it_never_managed_to_check(requests_mock):
    mock_submission(requests_mock, 111, sample_id=5)
    requests_mock.get(f"{BASE_URL}/rest/submission/112", status_code=404, json={"error_msg": "no such submission"})
    action = make(GetSubmissionResult)

    result = action.run({"submission_ids": [111, 112], "timeout": 0.05, "poll_interval": 0.01})

    assert result["pending_submission_ids"] == [112] and result["submission_ids"] == [111]
    assert "no such submission" in result["errors"][0]["error_msg"]
    assert action.outputs == {"pending": True}


def test_get_submission_result_fails_after_three_rounds_in_which_nothing_could_be_checked(requests_mock):
    poll = requests_mock.get(f"{BASE_URL}/rest/submission/111", status_code=401, json={"error_msg": "bad key"})

    with pytest.raises(Exception, match=r"No submission could be checked.*bad key"):
        make(GetSubmissionResult).run({"submission_ids": [111], "poll_interval": 0.01})

    assert poll.call_count == 3  # a wrong key is not retried for the whole timeout


@pytest.mark.parametrize(
    "arguments",
    [
        {"timeout": -1},
        {"timeout": float("nan")},
        {"timeout": float("inf")},
        {"poll_interval": 0},
        {"poll_interval": -5},
    ],
)
def test_get_submission_result_refuses_invalid_wait_settings(arguments):
    with pytest.raises(ValidationError):
        GetSubmissionResultArguments(submission_ids=[1], **arguments)


def test_the_manifest_matches_the_models():
    manifest = json.loads((ROOT / "action_get_submission_result.json").read_text(encoding="utf-8"))

    assert issubclass(GetSubmissionResult, Action)
    assert manifest["docker_parameters"] == "GetSubmissionResult"
    assert manifest["name"] == GetSubmissionResult.name
    assert manifest["arguments"] == GetSubmissionResultArguments.model_json_schema()
    assert manifest["results"] == GetSubmissionResultResults.model_json_schema()
