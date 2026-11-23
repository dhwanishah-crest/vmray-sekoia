"""StartUrlSubmission — submit a URL to VMRay and return at once.

The submission is the one Submit URL Sample makes, but the action does not wait for the analysis: it returns the IDs
of the submissions VMRay started. Give them to Check Submission Status to find out whether they finished. Consumes
quota, like Submit URL Sample.

Takes the `submitted` branch when VMRay started at least one submission and `submission_failed` otherwise.
"""

from vmray_modules.base import VMRayAction
from vmray_modules.models import StartUrlSubmissionArguments, StartUrlSubmissionResults
from vmray_modules.submit_helpers import submit_url


class StartUrlSubmission(VMRayAction):
    name = "Start URL Submission"
    description = (
        "Submit a URL to VMRay and return right away, without waiting for the analysis: check it later with Check "
        "Submission Status."
    )
    results_model = StartUrlSubmissionResults

    def run(self, arguments: StartUrlSubmissionArguments) -> StartUrlSubmissionResults:
        submission_ids, errors = submit_url(self, arguments)

        self.set_output("submitted" if submission_ids else "submission_failed", True)
        return StartUrlSubmissionResults(submitted=bool(submission_ids), submission_ids=submission_ids, errors=errors)
