"""StartFileSubmission — upload files from the playbook run's data storage to VMRay and return at once.

The upload is the one Submit File Sample makes (each file on its own; one that cannot be read or that VMRay refuses
is reported in `errors` and the others still go through), but the action does not wait for the analyses: it returns
the IDs of the submissions VMRay started. Give them to Check Submission Status to find out whether they finished.
Consumes quota, like Submit File Sample.

Takes the `submitted` branch when VMRay started at least one submission and `submission_failed` otherwise.
"""

from vmray_modules.base import VMRayAction
from vmray_modules.models import StartFileSubmissionArguments, StartFileSubmissionResults
from vmray_modules.submit_helpers import upload_files


class StartFileSubmission(VMRayAction):
    name = "Start File Submission"
    description = (
        "Submit files from the playbook run's storage to VMRay and return right away, without waiting for the "
        "analyses: check them later with Check Submission Status."
    )
    results_model = StartFileSubmissionResults

    def run(self, arguments: StartFileSubmissionArguments) -> StartFileSubmissionResults:
        submitted, submission_ids, errors = upload_files(self, arguments)

        self.set_output("submitted" if submission_ids else "submission_failed", True)
        return StartFileSubmissionResults(
            submitted=bool(submission_ids),
            submission_ids=submission_ids,
            submitted_files=submitted,
            errors=errors,
        )
