"""Shared by the submitting actions: the POST /sample/submit form parameters, and following the resulting
submissions until they finish.

Field names confirmed against the VMRay Platform REST API OpenAPI spec, v2026.2.1.
"""

import json
import time
from typing import Any

from pydantic import ValidationError

from vmray_modules.base import VMRayAction
from vmray_modules.client import VMRayClientError
from vmray_modules.models import Submission, SubmissionOptions

_FORM_OPTIONS = {
    "enable_reputation",
    "enable_whois",
    "analyzer_mode",
    "known_malicious",
    "known_benign",
    "max_jobs",
    "shareable",
    "max_recursive_samples",
}

_MAX_POLL_FAILURES = 3  # consecutive failed polls of one submission before it is given up


def submission_params(options: SubmissionOptions) -> dict[str, Any]:
    """Extra POST /sample/submit form fields. Unset options are omitted so the
    VMRay user's analyzer defaults apply; net_scheme_name and analysis_timeout
    aren't form fields and go inside the user_config JSON string instead."""
    params = options.model_dump(include=_FORM_OPTIONS, exclude_none=True)
    user_config = {"net_scheme_name": options.net_scheme_name, "timeout": options.analysis_timeout}
    user_config = {k: v for k, v in user_config.items() if v is not None}
    if user_config:
        params["user_config"] = json.dumps(user_config)
    return params


def submission_ids(response: dict[str, Any]) -> list[int]:
    """The distinct submission IDs of a POST /sample/submit response, in order."""
    return list(
        dict.fromkeys(
            s["submission_id"]
            for s in response.get("submissions") or []
            if isinstance(s, dict) and s.get("submission_id") is not None
        )
    )


def submit_errors(response: dict[str, Any]) -> list[dict[str, Any]]:
    """The `errors` of a POST /sample/submit response — why VMRay refused a sample even on a 200."""
    return [e for e in response.get("errors") or [] if isinstance(e, dict)]


class SubmittingAction(VMRayAction):
    """A VMRay action that submits samples, then waits for every resulting submission."""

    def follow_submissions(
        self, pending: list[int], errors: list[dict[str, Any]], query_retry_wait: float, timeout: float
    ) -> dict[str, Any]:
        """Polls every submission (GET /submission/{id}) until it reports `submission_finished`, sleeping
        `query_retry_wait` between rounds, and stops at `timeout`, reporting what is still pending. Takes the
        completed / timed_out / submission_failed branch and returns the results' fields; `errors` gets why a
        submission failed."""
        finished: list[Submission] = []
        failed: list[int] = []
        poll_failures: dict[int, int] = {}
        deadline = time.monotonic() + timeout
        while pending:
            still_pending = []
            for submission_id in pending:
                try:
                    updated = Submission.model_validate(self.client.update_submission(submission_id))
                except (VMRayClientError, ValidationError) as exc:
                    # one failed poll in a wait of up to 30 minutes must not lose the run — retry a few times
                    poll_failures[submission_id] = poll_failures.get(submission_id, 0) + 1
                    if poll_failures[submission_id] < _MAX_POLL_FAILURES:
                        still_pending.append(submission_id)
                    else:
                        failed.append(submission_id)
                        errors.append({"submission_id": submission_id, "error_msg": f"could not be followed: {exc}"})
                    continue
                poll_failures.pop(submission_id, None)
                if not updated.submission_finished:
                    still_pending.append(submission_id)
                elif updated.submission_has_errors:
                    failed.append(submission_id)
                    errors.append({"submission_id": submission_id, "error_msg": "VMRay finished it with an error"})
                else:
                    finished.append(updated)
            pending = still_pending

            remaining = deadline - time.monotonic()
            if not pending or remaining <= 0:
                break
            time.sleep(max(0.0, min(query_retry_wait, remaining)))

        sample_ids = list(
            dict.fromkeys(s.submission_sample_id for s in finished if s.submission_sample_id is not None)
        )
        timed_out = bool(pending)
        if timed_out:
            self.set_output("timed_out", True)
        elif finished:
            self.set_output("completed", True)
        else:  # every submission finished with an error
            self.set_output("submission_failed", True)
        return {
            "submissions": finished,
            "submission_ids": [s.submission_id for s in finished],
            "sample_ids": sample_ids,
            "pending_submission_ids": pending,
            "failed_submission_ids": failed,
            "timed_out": timed_out,
            "errors": errors,
        }
