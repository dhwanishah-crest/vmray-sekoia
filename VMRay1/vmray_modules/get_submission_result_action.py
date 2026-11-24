"""GetSubmissionResult — wait until submissions have finished, then return them.

Takes the submission IDs of Submit Sample or Submit URL and asks VMRay about each (GET /submission/{id}) every
`poll_interval` seconds until none is pending or `timeout` runs out. A playbook has no loop, so this one block covers
the whole wait: Submit, then Get Submission Result, then Build Report. A submission that has finished is not asked
about again.

Takes one of two branches:
  completed — every submission has finished and at least one finished without error. `submission_ids` and
              `sample_ids` are ready for Build Report; a failed one is listed in `failed_submission_ids`.
  failed    — no report to build: every submission finished with an error, or the wait timed out with a submission
              still running (`timed_out` is true and `pending_submission_ids` lists it). The ones that did finish
              are in the results either way.

A submission that cannot be checked is not called failed on the first try: the next check may well succeed. If it is
still unreachable when the wait ends, `errors` says why. When not one submission could be checked in three rounds in a
row (a wrong API key, VMRay down), the action raises an error instead. Costs no quota.
"""

import time
from typing import Any

from vmray_modules.base import VMRayAction
from vmray_modules.client import VMRayClientError
from vmray_modules.submission_helpers import poll_submissions
from vmray_modules.submission_models import GetSubmissionResultArguments, GetSubmissionResultResults, Submission

_BLIND_ROUNDS = 3  # rounds in a row in which not one submission could be checked, before the action fails


class GetSubmissionResult(VMRayAction):
    name = "Get Submission Result"
    description = (
        "Wait until VMRay submissions have finished, then return them: completed, or failed when one finished with "
        "an error or the wait timed out. Costs no quota."
    )
    results_model = GetSubmissionResultResults

    def run(self, arguments: GetSubmissionResultArguments) -> GetSubmissionResultResults:
        deadline = time.monotonic() + arguments.timeout
        finished: list[Submission] = []
        failed: list[int] = []
        pending = list(arguments.submission_ids)
        unchecked: dict[int, str] = {}
        blind_rounds = 0

        while True:
            polled = poll_submissions(self.client, pending)
            finished += polled.finished
            failed += polled.failed
            pending, unchecked = polled.pending, polled.unchecked

            # nothing could be looked at this round, and nothing ever has been: VMRay is not answering
            blind = len(unchecked) == len(polled.finished) + len(polled.failed) + len(polled.pending)
            blind_rounds = blind_rounds + 1 if blind and not (finished or failed) else 0
            if blind_rounds >= _BLIND_ROUNDS:
                raise VMRayClientError(
                    "No submission could be checked in VMRay: " + "; ".join(list(unchecked.values())[:3])
                )

            remaining = deadline - time.monotonic()
            if not pending or remaining <= 0:
                break
            time.sleep(max(0.0, min(arguments.poll_interval, remaining)))

        errors: list[dict[str, Any]] = [
            {"submission_id": submission_id, "error_msg": "VMRay finished it with an error"}
            for submission_id in failed
        ]
        errors += [
            {"submission_id": submission_id, "error_msg": f"could not be checked: {reason}"}
            for submission_id, reason in unchecked.items()
        ]

        self.set_output("completed" if finished and not pending else "failed", True)
        return GetSubmissionResultResults(
            all_finished=not pending,
            timed_out=bool(pending),
            submissions=finished,
            submission_ids=[s.submission_id for s in finished],
            sample_ids=list(
                dict.fromkeys(s.submission_sample_id for s in finished if s.submission_sample_id is not None)
            ),
            pending_submission_ids=pending,
            failed_submission_ids=failed,
            errors=errors,
        )
