"""Mocks and builders shared by the tests of Submit Sample, Submit URL and Get Submission Result."""

from vmray_modules.module_models import VMRayConfiguration, VMRayModule

BASE_URL = "https://eu.cloud.vmray.com"
SHA1 = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
OTHER = "b94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
URL = "http://evil.example/payload"


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
