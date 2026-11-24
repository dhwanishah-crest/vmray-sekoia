"""GetSubmissionResult — one look at whether submissions have finished.

Takes the submission IDs of Submit Sample or Submit URL (or of Submit Sample And Wait and Submit URL
Sample) and asks VMRay once for each (GET /submission/{id}). It does not wait and does not loop: a playbook decides
what to do while something is still running.

Takes one of three branches:
  completed — nothing is running and at least one submission finished without error. `submission_ids` and
              `sample_ids` are ready for Build Report; a failed one is listed in `failed_submission_ids`.
  pending   — at least one submission is still running (or could not be checked this time, which is told in
              `errors`). The ones that already finished are in the results too.
  failed    — every submission finished with an error.

A submission that cannot be checked is not called failed: it stays pending and says why, because the next check
may well succeed. When not one of them could be checked (a wrong API key, VMRay down), the action fails instead:
"pending" would tell the playbook something was running when nothing was looked at. Costs no quota.
"""

from typing import Any

from pydantic import ValidationError

from vmray_modules.base import VMRayAction
from vmray_modules.client import VMRayClientError
from vmray_modules.submission_models import GetSubmissionResultArguments, GetSubmissionResultResults, Submission
from vmray_modules.submit_helpers import submission_state


class GetSubmissionResult(VMRayAction):
    name = "Get Submission Result"
    description = (
        "Check once whether VMRay submissions have finished: completed, still pending or failed. Does not wait "
        "and costs no quota."
    )
    results_model = GetSubmissionResultResults

    def run(self, arguments: GetSubmissionResultArguments) -> GetSubmissionResultResults:
        finished: list[Submission] = []
        pending: list[int] = []
        failed: list[int] = []
        errors: list[dict[str, Any]] = []
        unchecked = 0

        for submission_id in arguments.submission_ids:
            try:
                submission = Submission.model_validate(self.client.update_submission(submission_id))
            except (VMRayClientError, ValidationError) as exc:
                unchecked += 1
                pending.append(submission_id)
                errors.append({"submission_id": submission_id, "error_msg": f"could not be checked: {exc}"})
                continue
            state = submission_state(submission)
            if state == "pending":
                pending.append(submission_id)
            elif state == "failed":
                failed.append(submission_id)
                errors.append({"submission_id": submission_id, "error_msg": "VMRay finished it with an error"})
            else:
                finished.append(submission)

        if unchecked == len(arguments.submission_ids):
            raise VMRayClientError(
                "No submission could be checked in VMRay: " + "; ".join(e["error_msg"] for e in errors[:3])
            )

        self.set_output("pending" if pending else "completed" if finished else "failed", True)
        return GetSubmissionResultResults(
            all_finished=not pending,
            submissions=finished,
            submission_ids=[s.submission_id for s in finished],
            sample_ids=list(
                dict.fromkeys(s.submission_sample_id for s in finished if s.submission_sample_id is not None)
            ),
            pending_submission_ids=pending,
            failed_submission_ids=failed,
            errors=errors,
        )
