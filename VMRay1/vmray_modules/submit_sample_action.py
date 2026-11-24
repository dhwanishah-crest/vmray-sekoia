"""SubmitSample — upload files from the playbook run's data storage to VMRay (POST /sample/submit) and return at once.

Each file is submitted on its own: one that cannot be read or that VMRay refuses is reported in `errors` and the
others still go through. The action does not wait for the analyses: it returns the IDs of the submissions VMRay
started. Give them to Get Submission Result, which waits for the analyses. Consumes quota.

Takes the `submitted` branch when VMRay started at least one submission and `submission_failed` otherwise.
"""

from vmray_modules.base import VMRayAction
from vmray_modules.submission_helpers import submit_sample
from vmray_modules.submission_models import SubmitSampleArguments, SubmitSampleResults


class SubmitSample(VMRayAction):
    name = "Submit Sample"
    description = (
        "Submit files from the playbook run's storage (e.g. malware fetched from an EDR) to VMRay and return "
        "right away, without waiting for the analysis. Follow it with Get Submission Result. Consumes quota."
    )
    results_model = SubmitSampleResults

    def run(self, arguments: SubmitSampleArguments) -> SubmitSampleResults:
        outcome = submit_sample(self, arguments)

        self.set_output(outcome.branch, True)
        return SubmitSampleResults(
            submitted=bool(outcome.submission_ids),
            submission_ids=outcome.submission_ids,
            submitted_files=outcome.submitted_files,
            errors=outcome.errors,
        )
