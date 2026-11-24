import json
from pathlib import Path

import pytest
from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.get_child_samples_action import GetChildSamples
from vmray_modules.models import VMRayConfiguration, VMRayModule
from vmray_modules.sample_models import GetChildSamplesArguments, GetChildSamplesResults

BASE_URL = "https://eu.cloud.vmray.com"
MANIFEST = Path(__file__).parents[1] / "action_get_child_samples.json"


def make_action():
    m = VMRayModule()
    m.configuration = VMRayConfiguration(base_url=BASE_URL, api_key="test-key")
    return GetChildSamples(module=m)


def ok(data):
    return {"result": "ok", "data": data}


def sample(sample_id, verdict="malicious", children=(), **extra):
    return {
        "sample_id": sample_id,
        "sample_filename": f"file-{sample_id}.bin",
        "sample_type": "Windows Exe (x86-64)",
        "sample_md5hash": f"{sample_id:032x}",
        "sample_sha1hash": f"{sample_id:040x}",
        "sample_sha256hash": f"{sample_id:064x}",
        "sample_verdict": verdict,
        "sample_verdict_reason_description": f"because {sample_id}",
        "sample_vti_score": 90 if verdict == "malicious" else 0,
        "sample_webif_url": f"https://eu.cloud.vmray.com/user/sample/view?id={sample_id}",
        "sample_child_sample_ids": list(children),
        **extra,
    }


def mock_samples(requests_mock, *samples):
    for s in samples:
        requests_mock.get(f"{BASE_URL}/rest/sample/{s['sample_id']}", json=ok(s))


def mock_tree(requests_mock):
    """42 (an archive) holds 43 (clean, an installer) and 44 (suspicious); 43 holds 45 (malicious)."""
    mock_samples(
        requests_mock,
        sample(42, "clean", children=[43, 44]),
        sample(43, "clean", children=[45]),
        sample(44, "suspicious"),
        sample(45, "malicious"),
    )


def test_lists_every_child_with_its_parent_and_depth(requests_mock):
    mock_tree(requests_mock)
    action = make_action()

    result = action.run({"sample_id": 42})

    assert result["has_children"] is True
    assert result["sample_id"] == 42
    assert result["sample_ids"] == [43, 44, 45]  # nearest levels first
    assert [(c["sample_id"], c["parent_sample_id"], c["depth"]) for c in result["children"]] == [
        (43, 42, 1),
        (44, 42, 1),
        (45, 43, 2),
    ]
    assert result["child_count"] == result["total_child_count"] == 3
    assert result["errors"] == {}
    assert action.outputs == {"has_children": True}


def test_each_child_carries_the_fields_a_playbook_asks_about(requests_mock):
    mock_tree(requests_mock)

    child = make_action().run({"sample_id": 42})["children"][2]

    assert child == {
        "sample_id": 45,
        "parent_sample_id": 43,
        "depth": 2,
        "name": "file-45.bin",
        "type": "Windows Exe (x86-64)",
        "md5": f"{45:032x}",
        "sha1": f"{45:040x}",
        "sha256": f"{45:064x}",
        "verdict": "malicious",
        "verdict_reason": "because 45",
        "vti_score": 90,
        "webif_url": "https://eu.cloud.vmray.com/user/sample/view?id=45",
        "child_count": 0,
    }


def test_a_child_reports_how_many_samples_it_holds(requests_mock):
    mock_tree(requests_mock)

    children = {c["sample_id"]: c for c in make_action().run({"sample_id": 42})["children"]}

    assert children[43]["child_count"] == 1
    assert children[44]["child_count"] == 0


def test_a_sample_without_children_takes_the_no_children_branch(requests_mock):
    mock_samples(requests_mock, sample(42))
    action = make_action()

    result = action.run({"sample_id": 42})

    assert result["has_children"] is False
    assert result["children"] == [] and result["sample_ids"] == []
    assert result["child_count"] == result["total_child_count"] == 0
    assert action.outputs == {"no_children": True}


def test_max_depth_stops_the_search_and_does_not_ask_for_deeper_samples(requests_mock):
    mock_tree(requests_mock)
    deeper = requests_mock.get(f"{BASE_URL}/rest/sample/45", json=ok(sample(45)))

    result = make_action().run({"sample_id": 42, "max_depth": 1})

    assert result["sample_ids"] == [43, 44]
    assert deeper.call_count == 0


def test_min_verdict_lists_only_children_at_least_that_severe(requests_mock):
    mock_tree(requests_mock)

    result = make_action().run({"sample_id": 42, "min_verdict": "suspicious"})

    assert result["sample_ids"] == [44, 45]
    assert result["child_count"] == 2
    assert result["total_child_count"] == 3  # the clean 43 was found, only not listed


def test_a_child_left_out_by_min_verdict_is_still_searched(requests_mock):
    """The malicious 45 sits inside the clean 43: filtering 43 out must not hide it."""
    mock_tree(requests_mock)

    result = make_action().run({"sample_id": 42, "min_verdict": "malicious"})

    assert result["sample_ids"] == [45]
    assert result["children"][0]["parent_sample_id"] == 43


def test_min_verdict_clean_leaves_out_children_without_a_known_verdict(requests_mock):
    mock_samples(requests_mock, sample(42, children=[43, 44]), sample(43, "clean"), sample(44, ""))

    assert make_action().run({"sample_id": 42, "min_verdict": "clean"})["sample_ids"] == [43]
    assert make_action().run({"sample_id": 42})["sample_ids"] == [43, 44]


def test_nothing_matching_min_verdict_takes_the_no_children_branch(requests_mock):
    mock_samples(requests_mock, sample(42, children=[43]), sample(43, "clean"))
    action = make_action()

    result = action.run({"sample_id": 42, "min_verdict": "malicious"})

    assert result["has_children"] is False
    assert result["total_child_count"] == 1
    assert action.outputs == {"no_children": True}


@pytest.mark.parametrize("value", ["malicous", "bad", "unknown"])
def test_an_invalid_min_verdict_is_an_error(requests_mock, value):
    mock_tree(requests_mock)

    with pytest.raises(ValueError, match="min_verdict has no valid value"):
        make_action().run({"sample_id": 42, "min_verdict": value})

    assert requests_mock.call_count == 0


def test_min_verdict_ignores_case_and_spaces(requests_mock):
    mock_tree(requests_mock)

    assert make_action().run({"sample_id": 42, "min_verdict": "  Malicious "})["sample_ids"] == [45]


def test_a_submission_id_is_resolved_to_its_sample(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/submission/7", json=ok({"submission_id": 7, "submission_sample_id": 42}))
    mock_tree(requests_mock)

    result = make_action().run({"submission_id": 7})

    assert result["sample_id"] == 42
    assert result["sample_ids"] == [43, 44, 45]


def test_sample_id_wins_over_submission_id(requests_mock):
    mock_tree(requests_mock)
    submission = requests_mock.get(f"{BASE_URL}/rest/submission/7", json=ok({"submission_sample_id": 99}))

    assert make_action().run({"sample_id": 42, "submission_id": 7})["sample_id"] == 42
    assert submission.call_count == 0


def test_a_submission_without_a_sample_is_an_error(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/submission/7", json=ok({"submission_id": 7}))

    with pytest.raises(ValueError, match="no sample for submission 7"):
        make_action().run({"submission_id": 7})


def test_neither_id_is_an_error():
    with pytest.raises(MissingActionArgumentError):
        make_action().run({})


def test_a_child_that_cannot_be_read_is_reported_and_the_others_are_still_listed(requests_mock):
    mock_samples(requests_mock, sample(42, children=[43, 44]), sample(44))
    requests_mock.get(f"{BASE_URL}/rest/sample/43", status_code=500, json={"error_msg": "boom"})

    result = make_action().run({"sample_id": 42})

    assert result["sample_ids"] == [44]
    assert "boom" in result["errors"]["child_sample:43"]


def test_a_child_that_is_not_a_sample_object_is_reported(requests_mock):
    mock_samples(requests_mock, sample(42, children=[43]))
    requests_mock.get(f"{BASE_URL}/rest/sample/43", json=ok({"unexpected": True}))

    result = make_action().run({"sample_id": 42})

    assert result["children"] == []
    assert "unexpected answer" in result["errors"]["child_sample:43"]


def test_the_sample_asked_for_must_be_readable(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/sample/42", status_code=404, json={"error_msg": "no such sample"})

    with pytest.raises(Exception, match="no such sample"):
        make_action().run({"sample_id": 42})


def test_a_tree_that_points_back_up_ends_and_lists_each_sample_once(requests_mock):
    """43 lists its own parent 42 and 44 lists 43 again: neither is walked twice."""
    mock_samples(
        requests_mock, sample(42, children=[43, 44]), sample(43, children=[42, 44]), sample(44, children=[43])
    )

    result = make_action().run({"sample_id": 42})

    assert result["sample_ids"] == [43, 44]
    assert result["errors"] == {}


def test_the_manifest_matches_the_models():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    assert manifest["docker_parameters"] == "GetChildSamples"
    assert manifest["arguments"] == GetChildSamplesArguments.model_json_schema()
    assert manifest["results"] == GetChildSamplesResults.model_json_schema()
