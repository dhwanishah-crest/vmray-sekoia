"""Get Sample IOCs, Mitre Attack Techniques, VTIs, Screenshots, Get Sample Report and Get Analysis Archive."""

import hashlib
import json
import re
from pathlib import Path

import pytest
from sekoia_automation.action import Action
from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules import models, sample_models
from vmray_modules.get_analysis_archive_action import GetAnalysisArchive
from vmray_modules.get_sample_iocs_action import GetSampleIocs
from vmray_modules.get_sample_mitre_attack_techniques_action import GetSampleMitreAttackTechniques, technique_ids
from vmray_modules.get_sample_report_action import GetSampleReport, extension_for
from vmray_modules.get_sample_screenshots_action import GetSampleScreenshots
from vmray_modules.get_sample_vtis_action import GetSampleVtis
from vmray_modules.sample_helpers import safe_name

BASE_URL = "https://eu.cloud.vmray.com"
ROOT = Path(__file__).parents[1]


@pytest.fixture(autouse=True)
def storage(data_storage):
    """Actions that save files write to data_path — every test gets a fresh one."""
    return data_storage


def make(action_class):
    m = models.VMRayModule()
    m.configuration = models.VMRayConfiguration(base_url=BASE_URL, api_key="test-key")
    return action_class(module=m)


def ok(data):
    return {"result": "ok", "data": data}


def saved(action, filename):
    return action.data_path.joinpath(filename).read_bytes()


# ---- Get Sample IOCs -------------------------------------------------------------------------------------------


IOCS = {
    "urls": [
        {"url": "http://evil.example", "severity": "malicious"},
        {"url": "http://x.example", "severity": "suspicious"},
    ],
    "domains": [{"domain": "evil.example", "severity": "malicious"}],
    "mutexes": [],
}


def test_iocs_are_returned_by_category_with_counts(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/sample/42/iocs", json=ok({"iocs": IOCS}))
    action = make(GetSampleIocs)

    result = action.run({"sample_id": 42})

    assert result["found"] is True
    assert result["sample_id"] == 42
    assert result["ioc_count"] == 3
    assert result["ioc_counts"] == {"urls": 2, "domains": 1, "mutexes": 0}
    assert result["iocs"] == IOCS
    assert action.outputs == {"found": True}


def test_no_iocs_takes_the_not_found_branch(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/sample/42/iocs", json=ok({"iocs": {"urls": []}}))
    action = make(GetSampleIocs)

    result = action.run({"sample_id": 42})

    assert result["found"] is False and result["ioc_count"] == 0
    assert action.outputs == {"not_found": True}


@pytest.mark.parametrize("answer", [{}, {"iocs": None}, {"iocs": ["not", "a", "dict"]}, {"iocs": {"urls": "oops"}}])
def test_an_unexpected_iocs_answer_means_none_found(requests_mock, answer):
    requests_mock.get(f"{BASE_URL}/rest/sample/42/iocs", json=ok(answer))

    assert make(GetSampleIocs).run({"sample_id": 42})["found"] is False


def test_one_severity_is_asked_of_vmray_and_two_or_none_fetch_everything(requests_mock):
    iocs = requests_mock.get(f"{BASE_URL}/rest/sample/42/iocs", json=ok({"iocs": {}}))

    make(GetSampleIocs).run({"sample_id": 42, "ioc_severity_filter": ["malicious"]})
    assert iocs.last_request.qs == {"ioc_severity": ["malicious"]}
    make(GetSampleIocs).run({"sample_id": 42, "ioc_severity_filter": ["malicious", "suspicious"]})
    assert iocs.last_request.qs == {}
    make(GetSampleIocs).run({"sample_id": 42})
    assert iocs.last_request.qs == {}


def test_a_severity_filter_without_a_valid_value_is_an_error(requests_mock):
    with pytest.raises(ValueError, match="ioc_severity_filter has no valid value"):
        make(GetSampleIocs).run({"sample_id": 42, "ioc_severity_filter": ["malicous"]})

    assert requests_mock.call_count == 0


def test_a_submission_id_is_resolved_to_its_sample(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/submission/7", json=ok({"submission_sample_id": 42}))
    requests_mock.get(f"{BASE_URL}/rest/sample/42/iocs", json=ok({"iocs": IOCS}))

    assert make(GetSampleIocs).run({"submission_id": 7})["sample_id"] == 42


def test_neither_id_is_an_error():
    with pytest.raises(MissingActionArgumentError):
        make(GetSampleIocs).run({})


# ---- Get Sample Mitre Attack Techniques ---------------------------------------------------------------------


def test_techniques_are_returned_with_their_ids(requests_mock):
    techniques = [
        {"technique_id": "T1055", "technique": "Process Injection"},
        {"id": "T1059"},
        {"technique_id": "T1055"},
        {"technique": "no id"},
    ]
    requests_mock.get(f"{BASE_URL}/rest/sample/42/mitre_attack", json=ok({"mitre_attack_techniques": techniques}))
    action = make(GetSampleMitreAttackTechniques)

    result = action.run({"sample_id": 42})

    assert result["found"] is True
    assert result["technique_count"] == 4
    assert result["technique_ids"] == ["T1055", "T1059"]  # once each, in order, skipping one without an id
    assert result["techniques"] == techniques
    assert action.outputs == {"found": True}


def test_no_techniques_takes_the_not_found_branch(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/sample/42/mitre_attack", json=ok({"mitre_attack_techniques": []}))
    action = make(GetSampleMitreAttackTechniques)

    result = action.run({"submission_id": None, "sample_id": 42})

    assert result["found"] is False and result["techniques"] == []
    assert action.outputs == {"not_found": True}


def test_technique_ids_ignores_what_is_not_a_text_id():
    assert technique_ids([{"technique_id": 5}, {"id": ""}, {"id": "T1"}]) == ["T1"]


# ---- Get Sample VTIs ---------------------------------------------------------------------------------------------


VTIS = {
    "threat_indicators": [
        {"operation": "Injects code", "score": 5},
        {"operation": "Reads files", "score": 2},
        {"operation": "No score"},
    ]
}


def test_vtis_are_returned_with_the_highest_score(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/sample/42/vtis", json=ok(VTIS))
    action = make(GetSampleVtis)

    result = action.run({"sample_id": 42})

    assert result["found"] is True
    assert result["vti_count"] == 3 and result["max_score"] == 5
    assert result["threat_indicators"] == VTIS["threat_indicators"]
    assert action.outputs == {"found": True}


def test_min_score_keeps_only_the_high_scoring_vtis(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/sample/42/vtis", json=ok(VTIS))

    result = make(GetSampleVtis).run({"sample_id": 42, "min_score": 3})

    assert [v["operation"] for v in result["threat_indicators"]] == ["Injects code"]
    assert result["vti_count"] == 1 and result["max_score"] == 5


def test_no_vti_reaching_min_score_takes_the_not_found_branch(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/sample/42/vtis", json=ok({"threat_indicators": [{"score": 1}]}))
    action = make(GetSampleVtis)

    result = action.run({"sample_id": 42, "min_score": 5})

    assert result["found"] is False and result["vti_count"] == 0 and result["max_score"] is None
    assert action.outputs == {"not_found": True}


def test_a_vti_without_a_numeric_score_never_reaches_a_minimum(requests_mock):
    requests_mock.get(
        f"{BASE_URL}/rest/sample/42/vtis", json=ok({"threat_indicators": [{"score": "5"}, {"score": True}]})
    )

    assert make(GetSampleVtis).run({"sample_id": 42, "min_score": 1})["found"] is False
    assert make(GetSampleVtis).run({"sample_id": 42})["vti_count"] == 2


# ---- Get Sample Screenshots --------------------------------------------------------------------------------------


def mock_analyses(requests_mock, sample_id, analyses):
    requests_mock.get(
        f"{BASE_URL}/rest/submission/sample/{sample_id}",
        json=ok([{"submission_id": 700, "submission_created": "2026-01-01T00:00:00"}]),
    )
    requests_mock.get(f"{BASE_URL}/rest/analysis/submission/700", json=ok(analyses))


def mock_archive(requests_mock, analysis_id, screenshots=None, status=200):
    summary = {"screenshots": [{"screenshot_archive_path": p} for p in (screenshots or [])]}
    requests_mock.get(
        f"{BASE_URL}/rest/analysis/{analysis_id}/archive/logs/summary.json",
        status_code=status,
        json=summary if status == 200 else {"error_msg": "not found"},
    )
    for path in screenshots or []:
        requests_mock.get(f"{BASE_URL}/rest/analysis/{analysis_id}/archive/{path}", content=f"png:{path}".encode())


def test_screenshots_are_saved_as_files_and_returned_as_paths(requests_mock):
    mock_analyses(requests_mock, 42, [{"analysis_id": 1, "analysis_created": "2026-01-01"}])
    mock_archive(requests_mock, 1, ["screenshots/a.png", "screenshots/b.png"])
    action = make(GetSampleScreenshots)

    result = action.run({"sample_id": 42})

    assert result["found"] is True and result["screenshot_count"] == 2
    assert [s["name"] for s in result["screenshots"]] == ["a.png", "b.png"]
    assert [f["path"] for f in result["files"]] == [s["path"] for s in result["screenshots"]]
    assert saved(action, result["files"][0]["path"]) == b"png:screenshots/a.png"
    assert result["screenshots"][0]["size"] == len(b"png:screenshots/a.png")
    assert result["screenshots"][0]["analysis_id"] == 1
    assert result["errors"] == {}
    assert action.outputs == {"found": True}


def test_the_newest_analysis_comes_first_and_max_screenshots_stops_the_search(requests_mock):
    mock_analyses(
        requests_mock,
        42,
        [{"analysis_id": 1, "analysis_created": "2026-01-01"}, {"analysis_id": 2, "analysis_created": "2026-06-01"}],
    )
    mock_archive(requests_mock, 2, ["screenshots/new1.png", "screenshots/new2.png"])
    older = requests_mock.get(f"{BASE_URL}/rest/analysis/1/archive/logs/summary.json", json={"screenshots": []})

    result = make(GetSampleScreenshots).run({"sample_id": 42, "max_screenshots": 2})

    assert [s["name"] for s in result["screenshots"]] == ["new1.png", "new2.png"]
    assert older.call_count == 0  # enough were saved already: the older analysis is not even read


def test_an_analysis_without_a_screenshot_list_is_not_an_error(requests_mock):
    mock_analyses(requests_mock, 42, [{"analysis_id": 1}])
    mock_archive(requests_mock, 1, status=404)
    action = make(GetSampleScreenshots)

    result = action.run({"sample_id": 42})

    assert result["found"] is False and result["errors"] == {}
    assert action.outputs == {"not_found": True}


def test_a_screenshot_that_cannot_be_read_is_reported_and_the_others_are_saved(requests_mock):
    mock_analyses(requests_mock, 42, [{"analysis_id": 1}])
    mock_archive(requests_mock, 1, ["screenshots/a.png", "screenshots/b.png"])
    requests_mock.get(
        f"{BASE_URL}/rest/analysis/1/archive/screenshots/a.png", status_code=500, json={"error_msg": "boom"}
    )

    result = make(GetSampleScreenshots).run({"sample_id": 42})

    assert [s["name"] for s in result["screenshots"]] == ["b.png"]
    assert "boom" in result["errors"]["screenshot:1/a.png"]


def test_a_screenshot_list_that_cannot_be_read_is_reported(requests_mock):
    mock_analyses(requests_mock, 42, [{"analysis_id": 1}])
    requests_mock.get(f"{BASE_URL}/rest/analysis/1/archive/logs/summary.json", content=b"not json")

    result = make(GetSampleScreenshots).run({"sample_id": 42})

    assert result["found"] is False
    assert "screenshot list could not be read" in result["errors"]["screenshots:1"]


def test_an_odd_screenshot_name_is_saved_under_a_safe_file_name(requests_mock):
    mock_analyses(requests_mock, 42, [{"analysis_id": 1}])
    mock_archive(requests_mock, 1, ["screenshots/evil name $(x).png"])
    action = make(GetSampleScreenshots)

    result = action.run({"sample_id": 42})

    filename = result["files"][0]["path"]
    assert "/" not in filename and " " not in filename and "$" not in filename
    assert action.data_path.joinpath(filename).exists()


@pytest.mark.parametrize("path", ["screenshots/../../user/me", "../x.png", "/etc/passwd"])
def test_a_screenshot_path_outside_the_archive_is_never_requested(requests_mock, path):
    """A client collapses ".." in a URL, so such a path would otherwise ask VMRay for some other endpoint."""
    mock_analyses(requests_mock, 42, [{"analysis_id": 1}])
    requests_mock.get(
        f"{BASE_URL}/rest/analysis/1/archive/logs/summary.json",
        json={"screenshots": [{"screenshot_archive_path": path}, {"screenshot_archive_path": "screenshots/ok.png"}]},
    )
    requests_mock.get(f"{BASE_URL}/rest/analysis/1/archive/screenshots/ok.png", content=b"png")
    elsewhere = requests_mock.get(re.compile(rf"{BASE_URL}/rest/(user|analysis/1/x).*"), json={})

    result = make(GetSampleScreenshots).run({"sample_id": 42})

    assert [s["name"] for s in result["screenshots"]] == ["ok.png"]
    assert result["errors"][f"screenshot:1/{path}"] == "not a path inside the analysis archive"
    assert elsewhere.call_count == 0


# ---- Get Analysis Archive ----------------------------------------------------------------------------------------


def test_the_whole_archive_is_saved_with_its_size_and_hash(requests_mock):
    archive = requests_mock.get(f"{BASE_URL}/rest/analysis/9/archive", content=b"PK-zip-bytes")
    action = make(GetAnalysisArchive)

    result = action.run({"analysis_id": 9})

    assert archive.call_count == 1
    assert result["size"] == len(b"PK-zip-bytes")
    assert result["sha256"] == hashlib.sha256(b"PK-zip-bytes").hexdigest()
    assert result["files"] == [{"path": result["file_name"]}]
    assert result["file_name"].endswith("archive.zip")
    assert saved(action, result["file_name"]) == b"PK-zip-bytes"


def test_one_file_of_the_archive_can_be_asked_for(requests_mock):
    one = requests_mock.get(f"{BASE_URL}/rest/analysis/9/archive/logs/summary.json", content=b'{"a": 1}')
    action = make(GetAnalysisArchive)

    result = action.run({"analysis_id": 9, "archive_path": " logs/summary.json "})

    assert one.call_count == 1
    assert result["file_name"].endswith("summary.json")
    assert saved(action, result["file_name"]) == b'{"a": 1}'


@pytest.mark.parametrize("path", ["../secret", "logs/../../x", "/etc/passwd"])
def test_an_archive_path_outside_the_archive_is_an_error(requests_mock, path):
    with pytest.raises(ValueError, match="inside the archive"):
        make(GetAnalysisArchive).run({"analysis_id": 9, "archive_path": path})

    assert requests_mock.call_count == 0


def test_an_archive_larger_than_the_limit_fails_by_its_declared_size(requests_mock):
    requests_mock.get(
        f"{BASE_URL}/rest/analysis/9/archive", content=b"x", headers={"Content-Length": str(5 * 1024 * 1024)}
    )

    with pytest.raises(Exception, match="larger than 1 MB"):
        make(GetAnalysisArchive).run({"analysis_id": 9, "max_size_mb": 1})


def test_an_archive_larger_than_the_limit_fails_by_what_arrives(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/analysis/9/archive", content=b"x" * (2 * 1024 * 1024))
    action = make(GetAnalysisArchive)

    with pytest.raises(Exception, match="larger than 1 MB"):
        action.run({"analysis_id": 9, "max_size_mb": 1})

    assert not list(action.data_path.glob("vmray-analysis-*"))  # nothing half-written


def test_a_vmray_error_fails_the_archive_download(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/analysis/9/archive", status_code=404, json={"error_msg": "no such analysis"})

    with pytest.raises(Exception, match="no such analysis"):
        make(GetAnalysisArchive).run({"analysis_id": 9})


# ---- Get Sample Report -------------------------------------------------------------------------------------------


def test_the_report_is_saved_as_received_with_its_content_type(requests_mock):
    requests_mock.get(
        f"{BASE_URL}/rest/sample/42/report", content=b"%PDF-1.7 report", headers={"Content-Type": "application/pdf"}
    )
    action = make(GetSampleReport)

    result = action.run({"sample_id": 42})

    assert result["sample_id"] == 42
    assert result["content_type"] == "application/pdf"
    assert result["file_name"].endswith("report.pdf")
    assert result["files"] == [{"path": result["file_name"]}]
    assert result["size"] == len(b"%PDF-1.7 report") and len(result["sha256"]) == 64
    assert saved(action, result["file_name"]) == b"%PDF-1.7 report"


def test_the_report_of_a_submission_is_found_through_its_sample(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/submission/7", json=ok({"submission_sample_id": 42}))
    requests_mock.get(f"{BASE_URL}/rest/sample/42/report", content=b"{}", headers={"Content-Type": "application/json"})

    result = make(GetSampleReport).run({"submission_id": 7})

    assert result["sample_id"] == 42 and result["file_name"].endswith("report.json")


@pytest.mark.parametrize(
    ("content_type", "extension"),
    [
        ("application/pdf", ".pdf"),
        ("application/json; charset=utf-8", ".json"),
        ("APPLICATION/ZIP", ".zip"),
        ("text/html", ".html"),
        ("application/octet-stream", ".bin"),
        ("", ".bin"),
    ],
)
def test_the_extension_follows_the_content_type(content_type, extension):
    assert extension_for(content_type) == extension


def test_a_report_larger_than_the_limit_fails(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/sample/42/report", content=b"x" * (2 * 1024 * 1024))

    with pytest.raises(Exception, match="larger than 1 MB"):
        make(GetSampleReport).run({"sample_id": 42, "max_size_mb": 1})


# ---- shared helpers ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [("shot 1.png", "shot_1.png"), ("../../etc/passwd", "passwd"), ("...", "file"), ("a" * 200, "a" * 80)],
)
def test_safe_name_keeps_letters_digits_and_dots_only(name, expected):
    assert safe_name(name) == expected


# ---- manifests ---------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("file", "docker", "action", "arguments", "results"),
    [
        (
            "action_get_sample_iocs.json",
            "GetSampleIocs",
            GetSampleIocs,
            sample_models.GetSampleIocsArguments,
            sample_models.GetSampleIocsResults,
        ),
        (
            "action_get_sample_mitre_attack_techniques.json",
            "GetSampleMitreAttackTechniques",
            GetSampleMitreAttackTechniques,
            sample_models.GetSampleMitreAttackTechniquesArguments,
            sample_models.GetSampleMitreAttackTechniquesResults,
        ),
        (
            "action_get_sample_vtis.json",
            "GetSampleVtis",
            GetSampleVtis,
            sample_models.GetSampleVtisArguments,
            sample_models.GetSampleVtisResults,
        ),
        (
            "action_get_sample_screenshots.json",
            "GetSampleScreenshots",
            GetSampleScreenshots,
            sample_models.GetSampleScreenshotsArguments,
            sample_models.GetSampleScreenshotsResults,
        ),
        (
            "action_get_sample_report.json",
            "GetSampleReport",
            GetSampleReport,
            sample_models.GetSampleReportArguments,
            sample_models.GetSampleReportResults,
        ),
        (
            "action_get_analysis_archive.json",
            "GetAnalysisArchive",
            GetAnalysisArchive,
            sample_models.GetAnalysisArchiveArguments,
            sample_models.GetAnalysisArchiveResults,
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
