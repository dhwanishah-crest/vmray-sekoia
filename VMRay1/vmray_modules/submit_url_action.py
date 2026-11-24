"""SubmitUrl — submit a URL to VMRay (POST /sample/submit) and return at once.

The action does not wait for the analysis: it returns the IDs of the submissions VMRay started. A playbook follows
them to Get Submission Result, which waits for the analysis. Consumes quota.

Takes the `submitted` branch when VMRay started at least one submission and `submission_failed` otherwise.
"""

from vmray_modules.base import VMRayAction
from vmray_modules.submission_helpers import submit_url
from vmray_modules.submission_models import SubmitUrlArguments, SubmitUrlResults


class SubmitUrl(VMRayAction):
    name = "Submit URL"
    description = (
        "Submit a URL to VMRay and return right away, without waiting for the analysis. Follow it with Get "
        "Submission Result. Consumes quota."
    )
    results_model = SubmitUrlResults

    def run(self, arguments: SubmitUrlArguments) -> SubmitUrlResults:
        outcome = submit_url(self, arguments)

        self.set_output(outcome.branch, True)
        return SubmitUrlResults(
            submitted=bool(outcome.submission_ids), submission_ids=outcome.submission_ids, errors=outcome.errors
        )
