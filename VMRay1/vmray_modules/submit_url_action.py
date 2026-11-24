"""SubmitUrl — submit a URL to VMRay and return at once.

The submission is the one Submit URL And Wait makes, but the action does not wait for the analysis: it returns the IDs
of the submissions VMRay started. Give them to Get Submission Result to find out whether they finished. Consumes
quota, like Submit URL And Wait.

Takes the `submitted` branch when VMRay started at least one submission and `submission_failed` otherwise.
"""

from vmray_modules.base import VMRayAction
from vmray_modules.submission_models import SubmitUrlArguments, SubmitUrlResults
from vmray_modules.submit_helpers import submit_url


class SubmitUrl(VMRayAction):
    name = "Submit URL"
    description = (
        "Submit a URL to VMRay and return right away, without waiting for the analysis. Follow it with Get "
        "Submission Result. Consumes quota."
    )
    results_model = SubmitUrlResults

    def run(self, arguments: SubmitUrlArguments) -> SubmitUrlResults:
        submission_ids, errors = submit_url(self, arguments)

        self.set_output("submitted" if submission_ids else "submission_failed", True)
        return SubmitUrlResults(submitted=bool(submission_ids), submission_ids=submission_ids, errors=errors)
