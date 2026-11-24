"""Submit URL: submit a URL to VMRay and return at once."""

import json
from pathlib import Path
from urllib.parse import parse_qs

import pytest
from pydantic import ValidationError
from sekoia_automation.action import Action

from tests.submit_mocks import BASE_URL, URL, make, mock_submission, mock_submit
from vmray_modules.submission_models import SubmitUrlArguments, SubmitUrlResults
from vmray_modules.submit_url_action import SubmitUrl

ROOT = Path(__file__).parents[1]


def test_submit_url_submits_and_returns_without_polling(requests_mock):
    submit = mock_submit(requests_mock, 111)
    poll = mock_submission(requests_mock, 111, finished=False)
    action = make(SubmitUrl)

    result = action.run({"sample_url": f" {URL} "})

    assert result == {"submitted": True, "submission_ids": [111], "errors": []}
    assert parse_qs(submit.last_request.text)["sample_url"] == [URL]
    assert poll.call_count == 0
    assert action.outputs == {"submitted": True}


def test_submit_url_refused_by_vmray_takes_the_failed_branch(requests_mock):
    requests_mock.post(f"{BASE_URL}/rest/sample/submit", status_code=402, json={"error_msg": "no quota left"})
    action = make(SubmitUrl)

    result = action.run({"sample_url": URL})

    assert result["submitted"] is False
    assert "no quota left" in result["errors"][0]["error_msg"]
    assert action.outputs == {"submission_failed": True}


def test_submit_url_with_a_200_and_no_submission_reports_why(requests_mock):
    mock_submit(requests_mock, errors=[{"error_msg": "invalid URL"}])

    result = make(SubmitUrl).run({"sample_url": URL})

    assert result["submitted"] is False
    assert result["errors"] == [{"error_msg": "invalid URL"}]


def test_submit_url_sends_the_reference_parameters(requests_mock):
    submit = mock_submit(requests_mock, 111)

    make(SubmitUrl).run(
        {
            "sample_url": URL,
            "tags": ["alert-AL1"],
            "max_recursive_samples": 10,
            "analysis_timeout": 120,
            "net_scheme_name": "Isolated",
        }
    )

    form = parse_qs(submit.last_request.text)
    assert form["sample_url"] == [URL]
    assert form["tags"] == ["alert-AL1"]
    assert form["reanalyze"] == ["True"]  # default: always a fresh analysis
    assert form["shareable"] == ["False"]
    assert form["max_recursive_samples"] == ["10"]
    assert json.loads(form["user_config"][0]) == {"net_scheme_name": "Isolated", "timeout": 120}


def test_submit_url_sends_the_default_options_only(requests_mock):
    """The recursion limit is always sent; archive settings are not (they only apply to files), and options left
    unset are not sent either."""
    submit = mock_submit(requests_mock, 111)

    make(SubmitUrl).run({"sample_url": URL})

    form = parse_qs(submit.last_request.text)
    assert form["max_recursive_samples"] == ["10"]
    assert not {"archive_password", "archive_action"} & set(form)
    assert not {"analyzer_mode", "max_jobs", "enable_reputation", "user_config", "analysis_caching"} & set(form)


def test_submit_url_cleans_the_tags(requests_mock):
    submit = mock_submit(requests_mock, 111)

    make(SubmitUrl).run({"sample_url": f"  {URL}  ", "tags": ["", " alert-1 ", "sekoia"]})

    form = parse_qs(submit.last_request.text)
    assert form["tags"] == ["alert-1,sekoia"]
    assert form["sample_url"] == [URL]


def test_submit_url_leaves_reanalyze_out_when_false(requests_mock):
    """Only a true reanalyze is sent; false leaves VMRay's own default in place."""
    submit = mock_submit(requests_mock, 111)

    make(SubmitUrl).run({"sample_url": URL, "reanalyze": False})

    assert "reanalyze" not in parse_qs(submit.last_request.text)


def test_submit_url_keeps_a_rejection_with_empty_fields(requests_mock):
    mock_submit(requests_mock, errors=[{"submission_filename": None, "error_msg": "bad", "code": 3}])
    action = make(SubmitUrl)

    result = action.run({"sample_url": URL})

    assert action.outputs == {"submission_failed": True}
    assert result["errors"][0]["error_msg"] == "bad"


def test_submit_url_returns_each_submission_once(requests_mock):
    mock_submit(requests_mock, 111, 111)

    assert make(SubmitUrl).run({"sample_url": URL})["submission_ids"] == [111]


@pytest.mark.parametrize(
    "arguments", [{"sample_url": "   "}, {"max_recursive_samples": -1}, {"max_recursive_samples": 11}]
)
def test_submit_url_refuses_invalid_inputs_before_submitting(requests_mock, arguments):
    submit = mock_submit(requests_mock, 111)

    with pytest.raises(ValidationError):
        make(SubmitUrl).run({"sample_url": URL, **arguments})
    assert submit.call_count == 0


def test_the_manifest_matches_the_models():
    manifest = json.loads((ROOT / "action_submit_url.json").read_text(encoding="utf-8"))

    assert issubclass(SubmitUrl, Action)
    assert manifest["docker_parameters"] == "SubmitUrl"
    assert manifest["name"] == SubmitUrl.name
    assert manifest["arguments"] == SubmitUrlArguments.model_json_schema()
    assert manifest["results"] == SubmitUrlResults.model_json_schema()
