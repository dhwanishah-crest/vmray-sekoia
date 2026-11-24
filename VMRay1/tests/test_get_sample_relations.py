import json
from pathlib import Path

import pytest
from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.get_sample_relations_action import GetSampleRelations, related_sample_ids
from vmray_modules.models import VMRayConfiguration, VMRayModule
from vmray_modules.sample_models import GetSampleRelationsArguments, GetSampleRelationsResults

BASE_URL = "https://eu.cloud.vmray.com"
MANIFEST = Path(__file__).parents[1] / "action_get_sample_relations.json"


def make_action():
    m = VMRayModule()
    m.configuration = VMRayConfiguration(base_url=BASE_URL, api_key="test-key")
    return GetSampleRelations(module=m)


def ok(data):
    return {"result": "ok", "data": data}


RELATIONS = [
    {
        "sample_relation_id": 1,
        "sample_relation_type": "embedded_file",
        "sample_relation_sample_id": 42,
        "sample_relation_child_sample_id": 43,
        "sample_relation_submission_id": 7,
    },
    {
        "sample_relation_id": 2,
        "sample_relation_type": "embedded_file",
        "sample_relation_sample_id": 42,
        "sample_relation_child_sample_id": 44,
        "sample_relation_submission_id": 7,
    },
]


def test_relations_of_a_sample_are_returned_as_vmray_sends_them(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/sample_relation/sample/42", json=ok(RELATIONS))
    action = make_action()

    result = action.run({"sample_id": 42})

    assert result["found"] is True
    assert result["relation_count"] == 2
    assert result["relations"] == RELATIONS
    assert result["related_sample_ids"] == [43, 44]  # the sample asked for is on every record: left out
    assert action.outputs == {"found": True}


def test_relations_of_a_submission(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/sample_relation/submission/7", json=ok(RELATIONS))

    result = make_action().run({"submission_id": 7})

    assert result["relation_count"] == 2
    assert result["related_sample_ids"] == [42, 43, 44]  # no sample was asked for: every one is related


def test_sample_id_wins_over_submission_id(requests_mock):
    by_sample = requests_mock.get(f"{BASE_URL}/rest/sample_relation/sample/42", json=ok(RELATIONS))
    by_submission = requests_mock.get(f"{BASE_URL}/rest/sample_relation/submission/7", json=ok([]))

    make_action().run({"sample_id": 42, "submission_id": 7})

    assert by_sample.call_count == 1 and by_submission.call_count == 0


def test_no_relation_takes_the_not_found_branch(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/sample_relation/sample/42", json=ok([]))
    action = make_action()

    result = action.run({"sample_id": 42})

    assert result["found"] is False
    assert result["relation_count"] == 0 and result["relations"] == [] and result["related_sample_ids"] == []
    assert action.outputs == {"not_found": True}


def test_a_single_record_that_is_not_wrapped_in_a_list_is_still_returned(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/sample_relation/sample/42", json=ok(RELATIONS[0]))

    result = make_action().run({"sample_id": 42})

    assert result["relations"] == [RELATIONS[0]]


def test_pages_are_followed(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/sample_relation/sample/42", json={**ok(RELATIONS[:1]), "continuation_id": 5})
    requests_mock.get(f"{BASE_URL}/rest/continuation/5", json=ok(RELATIONS[1:]))

    assert make_action().run({"sample_id": 42})["relation_count"] == 2


def test_neither_id_is_an_error():
    with pytest.raises(MissingActionArgumentError):
        make_action().run({})


def test_a_vmray_error_fails_the_action(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/sample_relation/sample/42", status_code=401, json={"error_msg": "bad key"})

    with pytest.raises(Exception, match="bad key"):
        make_action().run({"sample_id": 42})


def test_related_sample_ids_reads_every_sample_id_field_once_in_order():
    records = [
        {"sample_relation_id": 9, "other_sample_id": 5, "sample_id": 6, "flag": True, "sample_x_id": 8},
        {"sample_relation_id": 9, "other_sample_id": 5, "sample_id": "7", "parent_sample_id": True},
    ]

    assert related_sample_ids(records, None) == [5, 6]
    assert related_sample_ids(records, 5) == [6]  # ids, never relation ids, booleans or text


def test_the_manifest_matches_the_models():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    assert manifest["docker_parameters"] == "GetSampleRelations"
    assert manifest["arguments"] == GetSampleRelationsArguments.model_json_schema()
    assert manifest["results"] == GetSampleRelationsResults.model_json_schema()
