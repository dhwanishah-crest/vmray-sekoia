"""The actions chained the way a playbook chains them.

Between two nodes Sekoia stores a node's result as JSON and a later node reads fields of it into its own inputs. Each
step here does the same: the result is round-tripped through JSON, and the fields a playbook would pick (the
expressions the templates and the README use, such as `node.6['submission_ids']` or `node.8['sample_ids'][0]`) are
passed on to the next action. A chain that breaks here would break in a playbook.
"""

import json
from pathlib import Path

import pytest

from tests.test_build_report import BASE_URL, mock_full_sample, ok
from vmray_modules.build_report_action import BuildReport
from vmray_modules.extract_iocs_action import ExtractIocs
from vmray_modules.get_analysis_archive_action import GetAnalysisArchive
from vmray_modules.get_child_sample_report_action import GetChildSampleReport
from vmray_modules.get_child_samples_action import GetChildSamples
from vmray_modules.get_sample_iocs_action import GetSampleIocs
from vmray_modules.get_sample_mitre_attack_techniques_action import GetSampleMitreAttackTechniques
from vmray_modules.get_sample_relations_action import GetSampleRelations
from vmray_modules.get_sample_report_action import GetSampleReport
from vmray_modules.get_sample_screenshots_action import GetSampleScreenshots
from vmray_modules.get_sample_vtis_action import GetSampleVtis
from vmray_modules.get_samples_by_hash_action import GetSamplesByHash
from vmray_modules.get_submission_result_action import GetSubmissionResult
from vmray_modules.models import VMRayConfiguration, VMRayModule
from vmray_modules.render_report_action import RenderReport
from vmray_modules.submit_sample_action import SubmitSample
from vmray_modules.submit_sample_and_wait_action import SubmitSampleAndWait
from vmray_modules.submit_url_action import SubmitUrl
from vmray_modules.submit_url_and_wait_action import SubmitUrlAndWait

SHA1 = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
SHA256 = "d" * 64


@pytest.fixture(autouse=True)
def storage(data_storage):
    return data_storage


class Playbook:
    """Runs actions one after another and keeps every node's result as Sekoia would: as JSON."""

    def __init__(self, storage):
        self.storage = Path(storage)
        self.nodes = []

    def run(self, action_class, arguments):
        module = VMRayModule()
        module.configuration = VMRayConfiguration(base_url=BASE_URL, api_key="test-key")
        action = action_class(module=module)
        result = json.loads(json.dumps(action.run(arguments)))  # what the next node can read
        self.nodes.append((action_class.name, action.outputs))
        return result, action.outputs

    def file(self, name, content=b"MZ\x90\x00malware"):
        (self.storage / name).write_bytes(content)
        return name


@pytest.fixture
def playbook(storage):
    return Playbook(storage)


def mock_vmray(requests_mock):
    """Sample 42 (an archive) holds the malicious 43. Submission 7 made sample 42."""
    mock_full_sample(requests_mock, 42, children=[43])
    mock_full_sample(requests_mock, 43)
    requests_mock.post(
        f"{BASE_URL}/rest/sample/submit", json=ok({"submissions": [{"submission_id": 7}], "errors": []})
    )
    requests_mock.get(
        f"{BASE_URL}/rest/submission/7",
        json=ok({"submission_id": 7, "submission_finished": True, "submission_sample_id": 42}),
    )
    requests_mock.get(f"{BASE_URL}/rest/sample_relation/sample/42", json=ok([{"sample_relation_child_sample_id": 43}]))
    requests_mock.get(
        f"{BASE_URL}/rest/sample/sha256/{SHA256}", json=ok([{"sample_id": 42, "sample_verdict": "malicious"}])
    )
    requests_mock.get(
        f"{BASE_URL}/rest/sample/42/report", content=b"%PDF", headers={"Content-Type": "application/pdf"}
    )
    requests_mock.get(f"{BASE_URL}/rest/analysis/1/archive", content=b"PK")


def test_submit_a_file_follow_it_and_read_the_sample(requests_mock, playbook):
    """SentinelOne's files -> Submit Sample -> Get Submission Result -> every Get Sample action."""
    mock_vmray(requests_mock)
    files = [{"path": playbook.file(SHA1)}]  # the shape of SentinelOne's `files`, passed as is

    started, outputs = playbook.run(SubmitSample, {"files": files})
    assert outputs == {"submitted": True}

    result, outputs = playbook.run(GetSubmissionResult, {"submission_ids": started["submission_ids"]})
    assert outputs == {"completed": True}
    sample_id = result["sample_ids"][0]  # {{ node.N['sample_ids'][0] }}
    assert sample_id == 42

    iocs, _ = playbook.run(GetSampleIocs, {"sample_id": sample_id})
    vtis, _ = playbook.run(GetSampleVtis, {"sample_id": sample_id, "min_score": 3})
    mitre, _ = playbook.run(GetSampleMitreAttackTechniques, {"sample_id": sample_id})
    assert iocs["ioc_count"] == 1 and vtis["max_score"] == 5 and mitre["technique_count"] == 1
    assert iocs["sample_id"] == vtis["sample_id"] == mitre["sample_id"] == 42

    shots, outputs = playbook.run(GetSampleScreenshots, {"sample_id": sample_id})
    assert outputs == {"not_found": True} and shots["files"] == []  # the mock sample has no screenshots

    report, _ = playbook.run(GetSampleReport, {"submission_id": started["submission_ids"][0]})
    assert report["sample_id"] == 42 and report["content_type"] == "application/pdf"


def test_the_waiting_actions_give_the_same_ids_the_get_actions_take(requests_mock, playbook):
    mock_vmray(requests_mock)
    requests_mock.get(f"{BASE_URL}/rest/sample/42/iocs", json=ok({"iocs": {}}))
    files = [{"path": playbook.file(SHA1)}]

    waited, _ = playbook.run(SubmitSampleAndWait, {"files": files, "query_retry_wait": 0.01})
    by_url, _ = playbook.run(SubmitUrlAndWait, {"sample_url": "http://evil.example/x", "query_retry_wait": 0.01})

    for result in (waited, by_url):
        iocs, _ = playbook.run(GetSampleIocs, {"sample_id": result["sample_ids"][0]})
        assert iocs["sample_id"] == 42
        again, _ = playbook.run(GetSampleIocs, {"submission_id": result["submission_ids"][0]})
        assert again["sample_id"] == 42


def test_a_url_is_submitted_followed_and_reported(requests_mock, playbook):
    """Submit URL -> Get Submission Result -> Build Report -> Render Report -> Extract IOCs."""
    mock_vmray(requests_mock)

    started, _ = playbook.run(SubmitUrl, {"sample_url": "http://evil.example/x"})
    result, _ = playbook.run(GetSubmissionResult, {"submission_ids": started["submission_ids"]})
    report, _ = playbook.run(BuildReport, {"submission_ids": result["submission_ids"], "include_screenshots": False})
    rendered, _ = playbook.run(RenderReport, {"report_path": report["report_path"]})
    indicators, _ = playbook.run(ExtractIocs, {"report_path": report["report_path"]})

    assert report["sample_ids"] == [42]
    assert rendered["content"] and isinstance(rendered["screenshot_comments"], list)
    assert indicators["indicator_groups"]  # what a Foreach pushes to an IOC collection


def test_children_are_listed_reported_and_rendered(requests_mock, playbook):
    """Get Child Samples -> Get Child Sample Report (one per child) -> Render Report, as the README shows."""
    mock_vmray(requests_mock)

    children, outputs = playbook.run(GetChildSamples, {"sample_id": 42, "min_verdict": "malicious"})
    assert outputs == {"has_children": True}

    for child_id in children["sample_ids"]:  # the Foreach
        report, _ = playbook.run(
            GetChildSampleReport,
            {"parent_sample_id": children["sample_id"], "child_sample_id": child_id, "include_screenshots": False},
        )
        rendered, _ = playbook.run(RenderReport, {"report_path": report["report_path"]})
        assert report["sample_ids"] == [child_id] and rendered["content"]

    relations, _ = playbook.run(GetSampleRelations, {"sample_id": 42})
    assert relations["related_sample_ids"] == [43]


def test_a_hash_lookup_feeds_the_get_actions(requests_mock, playbook):
    mock_vmray(requests_mock)

    found, outputs = playbook.run(GetSamplesByHash, {"hashes": [SHA256]})
    assert outputs == {"found": True}

    vtis, _ = playbook.run(GetSampleVtis, {"sample_id": found["sample_ids"][0]})
    assert vtis["found"] is True


def test_a_saved_file_is_a_valid_input_for_the_next_file_action(requests_mock, playbook):
    """`files` of one action is `files` of Submit Sample: a saved archive can be submitted again as it is."""
    mock_vmray(requests_mock)

    archive, _ = playbook.run(GetAnalysisArchive, {"analysis_id": 1})
    again, outputs = playbook.run(SubmitSample, {"files": archive["files"]})

    assert outputs == {"submitted": True} and again["submitted_files"] == [archive["files"][0]["path"]]
