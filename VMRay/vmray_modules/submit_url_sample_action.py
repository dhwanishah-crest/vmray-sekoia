"""SubmitUrlSample — POST /sample/submit with a URL, then poll every resulting
submission until it finishes.

Polls ALL submissions in the submit response (GET /submission/{id}) until each
reports `submission_finished`, sleeping `query_retry_wait` between rounds, and
stops at `timeout`, reporting what is still pending.

Returns the finished submissions, their submission_ids and sample_ids. Building
the full report (VTIs, IOCs, MITRE ATT&CK) is a separate action that takes
either list of IDs.
"""

from vmray_modules.client import VMRayClientError
from vmray_modules.models import SubmitUrlSampleArguments, SubmitUrlSampleResults
from vmray_modules.submit_helpers import SubmittingAction, submission_ids, submission_params, submit_errors


class SubmitUrlSample(SubmittingAction):
    name = "Submit URL Sample"
    description = "Submit a URL to VMRay, wait until every resulting submission has finished, and return them."
    results_model = SubmitUrlSampleResults

    def run(self, arguments: SubmitUrlSampleArguments) -> SubmitUrlSampleResults:
        try:
            response = self.client.submit_url_sample(
                sample_url=arguments.sample_url,
                tags=arguments.tags,
                reanalyze=arguments.reanalyze,
                **submission_params(arguments),
            )
        except VMRayClientError as exc:  # e.g. an invalid URL or no quota left, refused with an HTTP error
            self.set_output("submission_failed", True)
            return SubmitUrlSampleResults(errors=[{"error_msg": str(exc)}])

        errors = submit_errors(response)
        pending = submission_ids(response)
        if not pending:
            # a 200 with no submission means VMRay rejected it — the reason is in `errors`
            self.set_output("submission_failed", True)
            return SubmitUrlSampleResults(errors=errors)

        return SubmitUrlSampleResults(
            **self.follow_submissions(pending, errors, arguments.query_retry_wait, arguments.timeout)
        )
