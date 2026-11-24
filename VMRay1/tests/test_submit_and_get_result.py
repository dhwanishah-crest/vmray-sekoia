"""Submit Sample, Submit URL and Get Submission Result: submit now, check later."""

import json
from pathlib import Path
from urllib.parse import parse_qs

import pytest
from pydantic import ValidationError
from sekoia_automation.action import Action
from vmray_modules.models import VMRayConfiguration, VMRayModule
from vmray_modules.submit_sample_and_wait_action import SubmitSampleAndWait
from vmray_modules.submit_url_and_wait_action import SubmitUrlAndWait

from vmray_modules.get_submission_result_action import GetSubmissionResult
from vmray_modules.submission_models import (
    GetSubmissionResultArguments,
    GetSubmissionResultResults,
    SubmitSampleArguments,
    SubmitSampleResults,
    SubmitUrlArguments,
    SubmitUrlResults,
)
from vmray_modules.submit_sample_action import SubmitSample
from vmray_modules.submit_url_action import SubmitUrl

BASE_URL = "https://eu.cloud.vmray.com"
SHA1 = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
OTHER = "b94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
URL = "http://evil.example/payload"
ROOT = Path(__file__).parents[1]


def make(action_class):
    m = VMRayModule()
    m.configuration = VMRayConfiguration(base_url=BASE_URL, api_key="test-key")
    return action_class(module=m)


def ok(data):
    return {"result": "ok", "data": data}


def mock_submit(requests_mock, *submission_ids, errors=()):
    return requests_mock.post(
        f"{BASE_URL}/rest/sample/submit",
        json=ok({"submissions": [{"submission_id": i} for i in submission_ids], "errors": list(errors)}),
    )


def mock_submission(requests_mock, submission_id, finished=True, sample_id=None, has_errors=False, **extra):
    return requests_mock.get(
        f"{BASE_URL}/rest/submission/{submission_id}",
        json=ok(
            {
                "submission_id": submission_id,
                "submission_finished": finished,
                "submission_has_errors": has_errors,
                "submission_sample_id": sample_id,
                **extra,
            }
        ),
    )


@pytest.fixture
def storage(data_storage):
    def write(name, content=b"MZ\x90\x00malware"):
        (Path(data_storage) / name).write_bytes(content)
        return name

    return write


# ---- Submit Sample ------------------------------------------------------------------------------------


def test_start_file_submission_uploads_and_returns_without_polling(requests_mock, storage):
    storage(SHA1)
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


def test_start_file_submission_returns_at_once_even_when_the_analysis_runs_for_a_long_time(requests_mock, storage):
    storage(SHA1)
    mock_submit(requests_mock, 111)
    mock_submission(requests_mock, 111, finished=False)

    result = make(SubmitSample).run({"files": [SHA1], "timeout": 1})  # no wait options: an extra input is ignored

    assert result["submission_ids"] == [111]


def test_start_file_submission_submits_each_file_and_keeps_going_after_a_bad_one(requests_mock, storage):
    storage(SHA1)
    storage(OTHER, b"")
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


def test_start_file_submission_with_nothing_accepted_takes_the_failed_branch(requests_mock, storage):
    storage(SHA1)
    mock_submit(requests_mock, errors=[{"error_msg": "no quota left"}])
    action = make(SubmitSample)

    result = action.run({"files": [SHA1]})

    assert result["submitted"] is False
    assert result["submission_ids"] == []
    assert result["errors"] == [{"file": SHA1, "error_msg": "no quota left"}]
    assert action.outputs == {"submission_failed": True}


def test_start_file_submission_rejects_a_path_outside_the_storage(requests_mock):
    mock_submit(requests_mock, 111)
    action = make(SubmitSample)

    result = action.run({"files": ["../secret", "/etc/passwd"]})

    assert result["submitted"] is False
    assert {e["error_msg"] for e in result["errors"]} == {"not a path inside the playbook run's data storage"}
    assert requests_mock.call_count == 0


def test_start_file_submission_needs_at_least_one_file():
    with pytest.raises(ValidationError):
        SubmitSampleArguments(files=[])


# ---- Submit URL -------------------------------------------------------------------------------------


def test_start_url_submission_submits_and_returns_without_polling(requests_mock):
    submit = mock_submit(requests_mock, 111)
    poll = mock_submission(requests_mock, 111, finished=False)
    action = make(SubmitUrl)

    result = action.run({"sample_url": f" {URL} "})

    assert result == {"submitted": True, "submission_ids": [111], "errors": []}
    assert parse_qs(submit.last_request.text)["sample_url"] == [URL]
    assert poll.call_count == 0
    assert action.outputs == {"submitted": True}


def test_start_url_submission_sends_the_same_options_as_submit_url_sample(requests_mock):
    submit = mock_submit(requests_mock, 111)

    make(SubmitUrl).run(
        {"sample_url": URL, "reanalyze": False, "tags": ["a", " b "], "max_recursive_samples": 3, "shareable": True}
    )
    start = parse_qs(submit.last_request.text)
    mock_submission(requests_mock, 111, sample_id=5)
    make(SubmitUrlAndWait).run(
        {
            "sample_url": URL,
            "reanalyze": False,
            "tags": ["a", " b "],
            "max_recursive_samples": 3,
            "shareable": True,
            "query_retry_wait": 0.01,
        }
    )

    assert parse_qs(submit.last_request.text) == start


def test_start_url_submission_refused_by_vmray_takes_the_failed_branch(requests_mock):
    requests_mock.post(f"{BASE_URL}/rest/sample/submit", status_code=402, json={"error_msg": "no quota left"})
    action = make(SubmitUrl)

    result = action.run({"sample_url": URL})

    assert result["submitted"] is False
    assert "no quota left" in result["errors"][0]["error_msg"]
    assert action.outputs == {"submission_failed": True}


def test_start_url_submission_with_a_200_and_no_submission_reports_why(requests_mock):
    mock_submit(requests_mock, errors=[{"error_msg": "invalid URL"}])

    result = make(SubmitUrl).run({"sample_url": URL})

    assert result["submitted"] is False
    assert result["errors"] == [{"error_msg": "invalid URL"}]


# ---- Get Submission Result ----------------------------------------------------------------------------------


def test_check_completed_when_every_submission_finished(requests_mock):
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


def test_check_pending_while_a_submission_still_runs_and_keeps_what_finished(requests_mock):
    mock_submission(requests_mock, 111, sample_id=5)
    mock_submission(requests_mock, 112, finished=False)
    action = make(GetSubmissionResult)

    result = action.run({"submission_ids": [111, 112]})

    assert result["all_finished"] is False
    assert result["pending_submission_ids"] == [112]
    assert result["submission_ids"] == [111] and result["sample_ids"] == [5]
    assert action.outputs == {"pending": True}


def test_check_makes_one_poll_per_submission_and_never_waits(requests_mock):
    poll = mock_submission(requests_mock, 111, finished=False)

    make(GetSubmissionResult).run({"submission_ids": [111]})

    assert poll.call_count == 1


def test_check_failed_when_every_submission_finished_with_an_error(requests_mock):
    mock_submission(requests_mock, 111, has_errors=True)
    mock_submission(requests_mock, 112, has_errors=True)
    action = make(GetSubmissionResult)

    result = action.run({"submission_ids": [111, 112]})

    assert result["all_finished"] is True
    assert result["failed_submission_ids"] == [111, 112]
    assert result["submission_ids"] == []
    assert [e["submission_id"] for e in result["errors"]] == [111, 112]
    assert action.outputs == {"failed": True}


def test_check_completed_when_some_failed_and_the_rest_finished(requests_mock):
    mock_submission(requests_mock, 111, sample_id=5)
    mock_submission(requests_mock, 112, has_errors=True)
    action = make(GetSubmissionResult)

    result = action.run({"submission_ids": [111, 112]})

    assert result["submission_ids"] == [111] and result["failed_submission_ids"] == [112]
    assert action.outputs == {"completed": True}


def test_check_a_submission_that_cannot_be_checked_stays_pending_with_the_reason(requests_mock):
    mock_submission(requests_mock, 111, sample_id=5)
    requests_mock.get(f"{BASE_URL}/rest/submission/112", status_code=404, json={"error_msg": "no such submission"})
    action = make(GetSubmissionResult)

    result = action.run({"submission_ids": [111, 112]})

    assert result["pending_submission_ids"] == [112]
    assert result["failed_submission_ids"] == []  # not failed: the next check may well work
    assert "could not be checked" in result["errors"][0]["error_msg"]
    assert "no such submission" in result["errors"][0]["error_msg"]
    assert action.outputs == {"pending": True}


def test_check_fails_when_not_one_submission_could_be_checked(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/submission/111", status_code=401, json={"error_msg": "bad key"})
    requests_mock.get(f"{BASE_URL}/rest/submission/112", status_code=401, json={"error_msg": "bad key"})

    with pytest.raises(Exception, match=r"No submission could be checked.*bad key"):
        make(GetSubmissionResult).run({"submission_ids": [111, 112]})


def test_check_an_answer_that_is_not_a_submission_is_unchecked_not_failed(requests_mock):
    mock_submission(requests_mock, 111, sample_id=5)
    requests_mock.get(f"{BASE_URL}/rest/submission/112", json=ok({"unexpected": True}))

    result = make(GetSubmissionResult).run({"submission_ids": [111, 112]})

    assert result["pending_submission_ids"] == [112]


def test_check_takes_one_id_or_a_list_and_checks_duplicates_once(requests_mock):
    poll = mock_submission(requests_mock, 111, sample_id=5)

    assert make(GetSubmissionResult).run({"submission_ids": 111})["submission_ids"] == [111]
    assert make(GetSubmissionResult).run({"submission_ids": [111, 111]})["submission_ids"] == [111]
    assert poll.call_count == 2  # one poll per call


def test_check_needs_at_least_one_submission_id():
    with pytest.raises(ValidationError):
        GetSubmissionResultArguments(submission_ids=[])


def test_check_takes_what_start_file_submission_returns(requests_mock, storage):
    """The chain a playbook builds: Submit Sample, later Get Submission Result, then Build Report."""
    storage(SHA1)
    mock_submit(requests_mock, 111)
    started = make(SubmitSample).run({"files": [SHA1]})
    mock_submission(requests_mock, 111, finished=False)

    first = make(GetSubmissionResult).run({"submission_ids": started["submission_ids"]})
    mock_submission(requests_mock, 111, sample_id=222)
    second = make(GetSubmissionResult).run({"submission_ids": started["submission_ids"]})

    assert first["pending_submission_ids"] == [111]
    assert second["submission_ids"] == [111] and second["sample_ids"] == [222]  # input for Build Report


# ---- the waiting actions are unchanged ------------------------------------------------------------------------


def test_submit_file_sample_still_waits(requests_mock, storage):
    storage(SHA1)
    mock_submit(requests_mock, 111)
    requests_mock.get(
        f"{BASE_URL}/rest/submission/111",
        [
            {"json": ok({"submission_id": 111, "submission_finished": False})},
            {"json": ok({"submission_id": 111, "submission_finished": True, "submission_sample_id": 222})},
        ],
    )
    action = make(SubmitSampleAndWait)

    result = action.run({"files": [SHA1], "query_retry_wait": 0.01})

    assert result["sample_ids"] == [222]
    assert action.outputs == {"completed": True}


def test_the_start_actions_do_not_offer_the_wait_options():
    for model in (SubmitSampleArguments, SubmitUrlArguments):
        assert "query_retry_wait" not in model.model_json_schema()["properties"]
        assert "timeout" not in model.model_json_schema()["properties"]


# ---- manifests ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("file", "docker", "action", "arguments", "results"),
    [
        (
            "action_submit_sample.json",
            "SubmitSample",
            SubmitSample,
            SubmitSampleArguments,
            SubmitSampleResults,
        ),
        (
            "action_submit_url.json",
            "SubmitUrl",
            SubmitUrl,
            SubmitUrlArguments,
            SubmitUrlResults,
        ),
        (
            "action_get_submission_result.json",
            "GetSubmissionResult",
            GetSubmissionResult,
            GetSubmissionResultArguments,
            GetSubmissionResultResults,
        ),
    ],
)
def test_the_manifest_matches_the_models(file, docker, action, arguments, results):
    manifest = json.loads((ROOT / file).read_text(encoding="utf-8"))

    assert issubclass(action, Action)
    assert manifest["docker_parameters"] == docker
    assert manifest["name"] == action.name
    assert manifest["arguments"] == arguments.model_json_schema()
    assert manifest["results"] == results.model_json_schema()
