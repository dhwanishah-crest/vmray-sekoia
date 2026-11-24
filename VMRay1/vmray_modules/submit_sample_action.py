"""SubmitSample — upload files from the playbook run's data storage to VMRay and return at once.

The upload is the one Submit Sample And Wait makes (each file on its own; one that cannot be read or that VMRay refuses
is reported in `errors` and the others still go through), but the action does not wait for the analyses: it returns
the IDs of the submissions VMRay started. Give them to Get Submission Result to find out whether they finished.
Consumes quota, like Submit Sample And Wait.

Takes the `submitted` branch when VMRay started at least one submission and `submission_failed` otherwise.
"""

from vmray_modules.base import VMRayAction
from vmray_modules.submission_models import SubmitSampleArguments, SubmitSampleResults
from vmray_modules.submit_helpers import upload_files


class SubmitSample(VMRayAction):
    name = "Submit Sample"
    description = (
        "Submit files from the playbook run's storage (e.g. malware fetched from an EDR) to VMRay and return "
        "right away, without waiting for the analysis. Follow it with Get Submission Result. Consumes quota."
    )
    results_model = SubmitSampleResults

    def run(self, arguments: SubmitSampleArguments) -> SubmitSampleResults:
        submitted, submission_ids, errors = upload_files(self, arguments)

        self.set_output("submitted" if submission_ids else "submission_failed", True)
        return SubmitSampleResults(
            submitted=bool(submission_ids),
            submission_ids=submission_ids,
            submitted_files=submitted,
            errors=errors,
        )
