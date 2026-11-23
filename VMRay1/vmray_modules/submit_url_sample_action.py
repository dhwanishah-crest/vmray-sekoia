"""SubmitUrlSample — POST /sample/submit with a URL, then poll every resulting
submission until it finishes.

Polls ALL submissions in the submit response (GET /submission/{id}) until each
reports `submission_finished`, sleeping `query_retry_wait` between rounds, and
stops at `timeout`, reporting what is still pending.

Returns the finished submissions, their submission_ids and sample_ids. Building
the full report (VTIs, IOCs, MITRE ATT&CK) is a separate action that takes
either list of IDs.
"""

from vmray_modules.models import SubmitUrlSampleArguments, SubmitUrlSampleResults
from vmray_modules.submit_helpers import SubmittingAction, submit_url


class SubmitUrlSample(SubmittingAction):
    name = "Submit URL Sample"
    description = "Submit a URL to VMRay, wait until every resulting submission has finished, and return them."
    results_model = SubmitUrlSampleResults

    def run(self, arguments: SubmitUrlSampleArguments) -> SubmitUrlSampleResults:
        pending, errors = submit_url(self, arguments)
        if not pending:
            self.set_output("submission_failed", True)
            return SubmitUrlSampleResults(errors=errors)

        return SubmitUrlSampleResults(
            **self.follow_submissions(pending, errors, arguments.query_retry_wait, arguments.timeout)
        )
