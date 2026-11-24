"""SubmitUrlAndWait — POST /sample/submit with a URL, then poll every resulting
submission until it finishes.

Polls ALL submissions in the submit response (GET /submission/{id}) until each
reports `submission_finished`, sleeping `query_retry_wait` between rounds, and
stops at `timeout`, reporting what is still pending.

Returns the finished submissions, their submission_ids and sample_ids. Building
the full report (VTIs, IOCs, MITRE ATT&CK) is a separate action that takes
either list of IDs.
"""

from vmray_modules.submission_models import SubmitUrlAndWaitArguments, SubmitUrlAndWaitResults
from vmray_modules.submit_helpers import SubmittingAction, submit_url


class SubmitUrlAndWait(SubmittingAction):
    name = "Submit URL And Wait"
    description = "Submit a URL to VMRay, wait until the analysis has finished and return the results. Consumes quota."
    results_model = SubmitUrlAndWaitResults

    def run(self, arguments: SubmitUrlAndWaitArguments) -> SubmitUrlAndWaitResults:
        pending, errors = submit_url(self, arguments)
        if not pending:
            self.set_output("submission_failed", True)
            return SubmitUrlAndWaitResults(errors=errors)

        return SubmitUrlAndWaitResults(
            **self.follow_submissions(pending, errors, arguments.query_retry_wait, arguments.timeout)
        )
