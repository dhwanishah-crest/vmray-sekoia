import json
from pathlib import Path

import pytest

from tests.test_build_report import BASE_URL, mock_full_sample, ok
from vmray_modules.get_child_sample_report_action import GetChildSampleReport
from vmray_modules.models import BuildReportResults, GetChildSampleReportArguments, VMRayConfiguration, VMRayModule

MANIFEST = Path(__file__).parents[1] / "action_get_child_sample_report.json"


@pytest.fixture(autouse=True)
def storage(data_storage):
    """The report is written to data_path — every test gets a fresh one."""
    return data_storage


def make_action():
    m = VMRayModule()
    m.configuration = VMRayConfiguration(base_url=BASE_URL, api_key="test-key")
    return GetChildSampleReport(module=m)


def report_of(arguments):
    action = make_action()
    result = action.run(arguments)
    return result, json.loads(action.data_path.joinpath(result["report_path"]).read_bytes())


def mock_parent(requests_mock, sample_id, children):
    requests_mock.get(
        f"{BASE_URL}/rest/sample/{sample_id}", json=ok({"sample_id": sample_id, "sample_child_sample_ids": children})
    )


def test_builds_the_full_report_of_a_direct_child(requests_mock):
    mock_parent(requests_mock, 40, [42])
    mock_full_sample(requests_mock, 42)

    result, report = report_of({"parent_sample_id": 40, "child_sample_id": 42})

    assert result["sample_ids"] == [42]
    assert result["errors"] == {}
    sample = report["samples"][0]
    assert sample["sample_id"] == 42
    assert sample["sample_threat_indicators"]["threat_indicators"][0]["score"] == 5
    assert sample["sample_mitre_attack"]["mitre_attack_techniques"][0]["id"] == "T1055"
    assert sample["sample_iocs"]["iocs"]["urls"][0]["url"] == "http://evil.example"
    assert [a["analysis_id"] for a in sample["sample_analyses"]] == [1, 2]
    # only the child is in the report, never its parent
    assert [s["sample_id"] for s in report["samples"]] == [42]


def test_finds_a_child_several_levels_down(requests_mock):
    mock_parent(requests_mock, 40, [41])
    mock_parent(requests_mock, 41, [42])
    mock_full_sample(requests_mock, 42)

    result, _ = report_of({"parent_sample_id": 40, "child_sample_id": 42})

    assert result["sample_ids"] == [42]


def test_the_childs_own_children_are_in_the_report_down_to_the_recursion_depth(requests_mock):
    mock_parent(requests_mock, 40, [42])
    mock_full_sample(requests_mock, 42, children=[43])
    mock_full_sample(requests_mock, 43)

    _, report = report_of({"parent_sample_id": 40, "child_sample_id": 42})
    _, no_recursion = report_of({"parent_sample_id": 40, "child_sample_id": 42, "max_recursion_depth": 0})

    assert [c["sample_id"] for c in report["samples"][0]["sample_child_samples"]] == [43]
    assert not no_recursion["samples"][0].get("sample_child_samples")


def test_a_sample_that_is_not_a_child_of_the_parent_fails_and_builds_nothing(requests_mock):
    mock_parent(requests_mock, 40, [41])
    mock_parent(requests_mock, 41, [])
    vtis = requests_mock.get(f"{BASE_URL}/rest/sample/99/vtis", json=ok({}))
    action = make_action()

    with pytest.raises(ValueError, match="Sample 99 is not a child of sample 40"):
        action.run({"parent_sample_id": 40, "child_sample_id": 99})

    assert vtis.call_count == 0
    assert not list(action.data_path.glob("vmray-report-*.json"))


def test_the_parent_itself_is_not_one_of_its_children(requests_mock):
    mock_parent(requests_mock, 40, [41])

    with pytest.raises(ValueError, match="is the parent itself"):
        make_action().run({"parent_sample_id": 40, "child_sample_id": 40})


def test_the_search_stops_at_the_child_and_does_not_read_the_rest_of_the_tree(requests_mock):
    mock_parent(requests_mock, 40, [42, 43])
    mock_full_sample(requests_mock, 42)
    other = requests_mock.get(f"{BASE_URL}/rest/sample/43", json=ok({"sample_id": 43}))

    report_of({"parent_sample_id": 40, "child_sample_id": 42})

    assert other.call_count == 0


@pytest.mark.parametrize("field", ["ioc_severity_filter", "analysis_verdict_filter"])
def test_a_filter_without_a_valid_value_is_an_error(requests_mock, field):
    mock_parent(requests_mock, 40, [42])

    with pytest.raises(ValueError, match=f"{field} has no valid value"):
        make_action().run({"parent_sample_id": 40, "child_sample_id": 42, field: ["malicous"]})

    assert requests_mock.call_count == 0


def test_the_report_has_the_shape_render_report_and_extract_iocs_take(requests_mock):
    """The result is Build Report's: a report_path, the sample ids and the errors."""
    mock_parent(requests_mock, 40, [42])
    mock_full_sample(requests_mock, 42)

    result, _ = report_of({"parent_sample_id": 40, "child_sample_id": 42})

    assert set(result) == set(BuildReportResults.model_fields)
    assert result["report_path"].startswith("vmray-report-")


def test_the_manifest_matches_the_models():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    assert manifest["docker_parameters"] == "GetChildSampleReport"
    assert manifest["arguments"] == GetChildSampleReportArguments.model_json_schema()
    assert manifest["results"] == BuildReportResults.model_json_schema()
