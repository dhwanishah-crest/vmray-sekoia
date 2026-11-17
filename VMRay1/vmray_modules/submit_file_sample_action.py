"""SubmitFileSample — upload files another node of the playbook run wrote to its data path (e.g. the malware
SentinelOne's Get malwares from threat fetched from an endpoint) with POST /sample/submit, then poll every resulting
submission until it finishes, exactly as Submit URL Sample does.

Each file is submitted on its own: one that cannot be read or that VMRay refuses is reported in `errors` and the
others still go through. The file is sent under its data-path name (SentinelOne names it by its SHA-1); VMRay
detects its type from the content.
"""

from pathlib import PurePosixPath
from typing import Any

from vmray_modules.base import UnsafeDataPathError
from vmray_modules.client import VMRayClientError
from vmray_modules.models import SubmitFileSampleArguments, SubmitFileSampleResults
from vmray_modules.submit_helpers import SubmittingAction, submission_ids, submission_params, submit_errors


class SubmitFileSample(SubmittingAction):
    name = "Submit File Sample"
    description = (
        "Submit files from the playbook run's storage (e.g. malware fetched from an EDR) to VMRay, wait until every "
        "resulting submission has finished, and return them."
    )
    results_model = SubmitFileSampleResults

    def run(self, arguments: SubmitFileSampleArguments) -> SubmitFileSampleResults:
        params = submission_params(arguments)
        errors: list[dict[str, Any]] = []
        submitted: list[str] = []
        pending: list[int] = []
        for path in arguments.files:
            try:
                content = self.read_data_file(path)
            except UnsafeDataPathError:
                errors.append({"file": path, "error_msg": "not a path inside the playbook run's data storage"})
                continue
            except FileNotFoundError:
                errors.append({"file": path, "error_msg": "no such file in the playbook run's data storage"})
                continue
            except Exception as exc:  # local or S3 storage, each with its own errors
                errors.append({"file": path, "error_msg": f"could not be read: {exc}"})
                continue
            if not content:
                errors.append({"file": path, "error_msg": "the file is empty"})
                continue

            try:
                response = self.client.submit_file_sample(
                    file_name=PurePosixPath(path.replace("\\", "/")).name,
                    content=content,
                    tags=arguments.tags,
                    reanalyze=arguments.reanalyze,
                    **params,
                )
            except VMRayClientError as exc:  # e.g. no quota left, or a file VMRay refuses with an HTTP error
                errors.append({"file": path, "error_msg": str(exc)})
                continue

            errors.extend({"file": path, **e} for e in submit_errors(response))
            ids = submission_ids(response)
            if ids:
                submitted.append(path)
                pending.extend(i for i in ids if i not in pending)
            elif not submit_errors(response):  # a 200 with neither: say so rather than drop the file silently
                errors.append({"file": path, "error_msg": "VMRay returned no submission for this file"})

        if not pending:
            self.set_output("submission_failed", True)
            return SubmitFileSampleResults(errors=errors)

        return SubmitFileSampleResults(
            submitted_files=submitted,
            **self.follow_submissions(pending, errors, arguments.query_retry_wait, arguments.timeout),
        )
