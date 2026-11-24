"""GetSubmissionResult — wait until submissions have finished, then return them.

Takes the submission IDs of Submit Sample or Submit URL and asks VMRay about each (GET /submission/{id}) every
`poll_interval` seconds until none is pending or `timeout` runs out. A playbook has no loop, so this one block covers
the whole wait: Submit, then Get Submission Result, then Build Report. A submission that has finished is not asked
about again. `timeout` 0 checks once and returns at once.

Takes one of three branches:
  completed — nothing is pending and at least one submission finished without error. `submission_ids` and
              `sample_ids` are ready for Build Report; a failed one is listed in `failed_submission_ids`.
  pending   — the wait timed out with a submission still running (`timed_out` is true), or `timeout` was 0 and one
              is running. The ones that already finished are in the results too.
  failed    — every submission finished with an error.

A submission that cannot be checked is not called failed: it stays pending and says why, because the next check
may well succeed. When not one submission could be checked in three rounds in a row (a wrong API key, VMRay down),
the action fails instead: "pending" would tell the playbook something was running when nothing was looked at.
Costs no quota.
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
        "Wait until VMRay submissions have finished, then return them: completed, still pending when the wait timed "
        "out, or failed. Costs no quota."
    )
    results_model = GetSubmissionResultResults

    def run(self, arguments: GetSubmissionResultArguments) -> GetSubmissionResultResults:
        waits = arguments.timeout > 0
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
            if blind_rounds >= (_BLIND_ROUNDS if waits else 1):
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

        self.set_output("pending" if pending else "completed" if finished else "failed", True)
        return GetSubmissionResultResults(
            all_finished=not pending,
            timed_out=waits and bool(pending),
            submissions=finished,
            submission_ids=[s.submission_id for s in finished],
            sample_ids=list(
                dict.fromkeys(s.submission_sample_id for s in finished if s.submission_sample_id is not None)
            ),
            pending_submission_ids=pending,
            failed_submission_ids=failed,
            errors=errors,
        )
