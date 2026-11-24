"""SubmitSampleAndWait — upload files another node of the playbook run wrote to its data path (e.g. the malware
SentinelOne's Get malwares from threat fetched from an endpoint) with POST /sample/submit, then poll every resulting
submission until it finishes, exactly as Submit URL And Wait does.

Each file is submitted on its own: one that cannot be read or that VMRay refuses is reported in `errors` and the
others still go through. The file is sent under its data-path name (SentinelOne names it by its SHA-1); VMRay
detects its type from the content. The upload is shared with Submit Sample, which does not wait.
"""

from vmray_modules.submission_models import SubmitSampleAndWaitArguments, SubmitSampleAndWaitResults
from vmray_modules.submit_helpers import SubmittingAction, upload_files


class SubmitSampleAndWait(SubmittingAction):
    name = "Submit Sample And Wait"
    description = (
        "Submit files from the playbook run's storage (e.g. malware fetched from an EDR) to VMRay, wait until "
        "every analysis has finished and return the results. Consumes quota."
    )
    results_model = SubmitSampleAndWaitResults

    def run(self, arguments: SubmitSampleAndWaitArguments) -> SubmitSampleAndWaitResults:
        submitted, pending, errors = upload_files(self, arguments)

        if not pending:
            self.set_output("submission_failed", True)
            return SubmitSampleAndWaitResults(errors=errors)

        return SubmitSampleAndWaitResults(
            submitted_files=submitted,
            **self.follow_submissions(pending, errors, arguments.query_retry_wait, arguments.timeout),
        )
