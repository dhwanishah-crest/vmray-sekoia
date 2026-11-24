"""Shared by the submission actions: the POST /sample/submit form parameters, the two submit functions and the check
of where submissions stand.

Both submit functions return a `Submitted`, so Submit Sample and Submit URL read the same way. Neither waits for the
analysis: Get Submission Result does, with `poll_submissions` once per round.

Field names confirmed against the VMRay Platform REST API OpenAPI spec, v2026.2.1.
"""

import json
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from pydantic import ValidationError

from vmray_modules.base import UnsafeDataPathError, VMRayAction
from vmray_modules.client import VMRayClient, VMRayClientError
from vmray_modules.submission_models import (
    Submission,
    SubmissionOptions,
    SubmitSampleArguments,
    SubmitUrlArguments,
)

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


@dataclass
class Submitted:
    """What a submit function did: the submissions VMRay started, why it refused the rest, and for files which of
    them it accepted. No submission ID means VMRay took nothing: the reason is in `errors`."""

    submission_ids: list[int] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    submitted_files: list[str] = field(default_factory=list)

    @property
    def branch(self) -> str:
        """The output branch of the submit actions."""
        return "submitted" if self.submission_ids else "submission_failed"


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


def submit_url(action: VMRayAction, arguments: SubmitUrlArguments) -> Submitted:
    """POST the URL. A refusal with an HTTP error (an invalid URL, no quota left) and a 200 that started nothing both
    end up in `errors`."""
    try:
        response = action.client.submit_url(
            sample_url=arguments.sample_url,
            tags=arguments.tags,
            reanalyze=arguments.reanalyze,
            **submission_params(arguments),
        )
    except VMRayClientError as exc:
        return Submitted(errors=[{"error_msg": str(exc)}])
    return Submitted(submission_ids=submission_ids(response), errors=submit_errors(response))


def read_file_to_submit(action: VMRayAction, path: str) -> bytes:
    """The content of one file of the playbook run's data storage, or a ValueError saying why it cannot be sent."""
    try:
        content = action.read_data_file(path)
    except UnsafeDataPathError as exc:
        raise ValueError("not a path inside the playbook run's data storage") from exc
    except FileNotFoundError as exc:
        raise ValueError("no such file in the playbook run's data storage") from exc
    except Exception as exc:  # local or S3 storage, each with its own errors
        raise ValueError(f"could not be read: {exc}") from exc
    if not content:
        raise ValueError("the file is empty")
    return content


def submit_sample(action: VMRayAction, arguments: SubmitSampleArguments) -> Submitted:
    """Upload each file of the playbook run's data storage on its own: one that cannot be read or that VMRay refuses
    is reported in `errors` and the others still go through. The file is sent under its data-path name (SentinelOne
    names it by its SHA-1); VMRay detects its type from the content."""
    params = submission_params(arguments)
    result = Submitted()
    for path in arguments.files:
        try:
            content = read_file_to_submit(action, path)
        except ValueError as exc:
            result.errors.append({"file": path, "error_msg": str(exc)})
            continue

        try:
            response = action.client.submit_sample(
                file_name=PurePosixPath(path.replace("\\", "/")).name,
                content=content,
                tags=arguments.tags,
                reanalyze=arguments.reanalyze,
                **params,
            )
        except VMRayClientError as exc:  # e.g. no quota left, or a file VMRay refuses with an HTTP error
            result.errors.append({"file": path, "error_msg": str(exc)})
            continue

        refusals = submit_errors(response)
        result.errors.extend({"file": path, **e} for e in refusals)
        ids = submission_ids(response)
        if ids:
            result.submitted_files.append(path)
            result.submission_ids.extend(i for i in ids if i not in result.submission_ids)
        elif not refusals:  # a 200 with neither: say so rather than drop the file silently
            result.errors.append({"file": path, "error_msg": "VMRay returned no submission for this file"})
    return result


@dataclass
class Polled:
    """One look at some submissions (one GET /submission/{id} each): the ones that finished, the ones that finished
    with an error, and the ones still pending. A submission that could not be checked this time is pending too, with
    the reason in `unchecked`: the next look may well work."""

    finished: list[Submission] = field(default_factory=list)
    failed: list[int] = field(default_factory=list)
    pending: list[int] = field(default_factory=list)
    unchecked: dict[int, str] = field(default_factory=dict)


def poll_submissions(client: VMRayClient, submission_ids: list[int]) -> Polled:
    """Ask VMRay once about each submission and sort them by where they stand."""
    polled = Polled()
    for submission_id in submission_ids:
        try:
            submission = Submission.model_validate(client.get_submission(submission_id))
        except (VMRayClientError, ValidationError) as exc:
            polled.pending.append(submission_id)
            polled.unchecked[submission_id] = str(exc)
            continue
        state = submission.state
        if state == "pending":
            polled.pending.append(submission_id)
        elif state == "failed":
            polled.failed.append(submission_id)
        else:
            polled.finished.append(submission)
    return polled
