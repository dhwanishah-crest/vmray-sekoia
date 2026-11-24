"""Models of the submit actions (Submit Sample, Submit URL) and of Get Submission Result, which waits for them.

Field names on VMRay-sourced models follow the VMRay Platform REST API verbatim (see module_models.py).

The inputs of a submitting action are declared in the order a playbook author fills them in: the sample first (the
files or the URL), then Re-analyze and Tags, then the VMRay options. The bases of the argument models list the
options first and the sample input last, because pydantic orders inherited fields from the last base to the first.
"""

from typing import Any

from pydantic import BaseModel, Field, field_validator
from pydantic.json_schema import SkipJsonSchema

from vmray_modules.module_models import hide_empty_defaults

# --------------------------------------------------------------------------
# Inputs shared by every submitting action
# --------------------------------------------------------------------------


class SubmissionOptions(BaseModel):
    """POST /sample/submit form fields — without the archive settings, which only apply
    to submitted files. Options left empty are not sent, so the VMRay user's own
    analyzer settings apply. `net_scheme_name` and `analysis_timeout` are not form
    fields: they ride inside the `user_config` JSON string (as `net_scheme_name` and
    `timeout`)."""

    model_config = {"json_schema_extra": hide_empty_defaults}

    shareable: bool = Field(
        default=False,
        title="Share with VirusTotal",
        description="If set to true, the hash of the sample will be shared with VirusTotal.",
    )
    max_recursive_samples: int = Field(
        default=10,
        ge=0,
        le=10,
        title="Max recursive samples",
        description="The maximum amount of recursive samples (files found inside the sample) which will be analyzed, "
        "at most 10. 0 disables recursion.",
    )
    max_jobs: int | SkipJsonSchema[None] = Field(
        default=None,
        title="Max jobs",
        description="Limits the amount of jobs that can be created by jobrules for a submission.",
    )
    enable_reputation: bool | SkipJsonSchema[None] = Field(
        default=None,
        title="Enable reputation lookups",
        description="If set to true, reputation lookups will be performed for submitted samples and analysis "
        "artifacts (file hash and URL lookups) by the VMRay cloud reputation service and additional third party "
        "services. The user analyzer setting is used as default value for this parameter.",
    )
    enable_whois: bool | SkipJsonSchema[None] = Field(
        default=None,
        title="Enable WHOIS",
        description="If set to true, domains seen during analyses are queried with external WHOIS service. The user "
        "analyzer setting is used as default value for this parameter.",
    )
    analyzer_mode: str | SkipJsonSchema[None] = Field(
        default=None,
        title="Analyzer mode",
        description="Specifies which types of analyzers will be used for analyzing this sample. Supported strings "
        "are 'reputation', 'reputation_static', 'reputation_static_dynamic', 'static_dynamic', and 'static'. The "
        "user analyzer setting is used as default value for this parameter.",
    )
    known_malicious: bool | SkipJsonSchema[None] = Field(
        default=None,
        title="Pre-filter known malicious",
        description="If set to true, triage will be used to pre-filter known malicious samples by results of "
        "reputation lookup (if allowed) and static analysis. The user analyzer setting is used as default value "
        "for this parameter.",
    )
    known_benign: bool | SkipJsonSchema[None] = Field(
        default=None,
        title="Pre-filter known benign",
        description="If set to true, triage will be used to pre-filter known benign samples by results of "
        "reputation lookup (if allowed) and static analysis. The user analyzer setting is used as default value "
        "for this parameter.",
    )
    analysis_timeout: int | SkipJsonSchema[None] = Field(
        default=None, title="Analysis timeout (s)", description="Analysis timeout in seconds."
    )
    net_scheme_name: str | SkipJsonSchema[None] = Field(
        default=None, title="Network scheme name", description="Name of the network scheme to analyze with."
    )


class ReanalyzeAndTags(BaseModel):
    """What every submitting action takes besides the sample and the options."""

    reanalyze: bool = Field(
        default=True,
        title="Re-analyze known samples",
        description="If set to true, known samples will be re-analyzed on submission. This is enabled by default.",
    )
    tags: list[str] = Field(
        default_factory=lambda: ["sekoia"],
        title="Tags",
        description="Tags to attach to the sample.",
    )


class UrlInput(BaseModel):
    sample_url: str = Field(
        ...,
        min_length=1,
        title="URL",
        description="URL to submit for detonation. VMRay opens it in a browser and also analyses what it downloads.",
    )

    @field_validator("sample_url", mode="before")
    @classmethod
    def _strip(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class FilesInput(BaseModel):
    files: list[str] = Field(
        ...,
        title="Files",
        description="Files to submit, as paths in the playbook run's data storage — e.g. the `files` of "
        'SentinelOne\'s Get malwares from threat, given as is: a list of {"path": ...} objects or of paths.',
    )

    @field_validator("files", mode="before")
    @classmethod
    def _paths(cls, value: Any) -> Any:
        """Takes the output of a file-producing action as is: one path or {"path": ...}, or a list of them.
        Duplicates are dropped, so a file listed twice is submitted (and billed) once."""
        if isinstance(value, str | dict):
            value = [value]
        if not isinstance(value, list):
            return value
        paths: list[str] = []
        for item in value:
            path = item.get("path") if isinstance(item, dict) else item
            if not isinstance(path, str):
                raise ValueError('each file must be a path, or an object with a "path"')
            if path.strip():
                paths.append(path.strip())
        return list(dict.fromkeys(paths))

    @field_validator("files", mode="after")
    @classmethod
    def _at_least_one(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("at least one file is required")
        return value


# --------------------------------------------------------------------------
# One submission, as VMRay returns it
# --------------------------------------------------------------------------


class Submission(BaseModel):
    """One submission object, as GET /submission/{id} returns it once finished."""

    model_config = {"extra": "allow"}

    submission_id: int = Field(..., title="Submission ID")
    submission_sample_id: int | None = Field(default=None, title="Submission Sample ID")
    submission_finished: bool | None = None
    submission_has_errors: bool | None = None
    submission_verdict: str | None = None
    submission_score: int | None = None
    submission_original_url: str | None = Field(default=None, title="Submission Original URL")
    submission_consumed_quota: int | None = None
    submission_webif_url: str | None = Field(default=None, title="Submission Webif URL")

    @property
    def state(self) -> str:
        """Where the submission stands: "pending" until VMRay reports `submission_finished`, then "failed" if it
        finished with an error, else "finished"."""
        if not self.submission_finished:
            return "pending"
        return "failed" if self.submission_has_errors else "finished"


# --------------------------------------------------------------------------
# Submit URL / Submit Sample — return at once with the submission IDs (Get Submission Result follows them)
# --------------------------------------------------------------------------


class SubmitUrlArguments(SubmissionOptions, ReanalyzeAndTags, UrlInput):
    pass


class SubmitSampleArguments(SubmissionOptions, ReanalyzeAndTags, FilesInput):
    pass


class SubmitResults(BaseModel):
    submitted: bool = Field(description="True when VMRay accepted at least one submission.")
    submission_ids: list[int] = Field(
        default_factory=list,
        title="Submission IDs",
        description="IDs of the submissions VMRay started. They are not finished yet: give them to Get Submission "
        "Result.",
    )
    errors: list[dict[str, Any]] = Field(
        default_factory=list, description="Errors VMRay returned on submit, and the files it could not take."
    )


class SubmitUrlResults(SubmitResults):
    pass


class SubmitSampleResults(SubmitResults):
    submitted_files: list[str] = Field(
        default_factory=list,
        title="Submitted Files",
        description="Files VMRay accepted. A file that could not be read or was refused is in `errors`.",
    )


# --------------------------------------------------------------------------
# Get Submission Result — waits until submissions have finished
# --------------------------------------------------------------------------


class GetSubmissionResultArguments(BaseModel):
    submission_ids: list[int] = Field(
        ...,
        title="Submission IDs",
        description="VMRay submission IDs to wait for — e.g. the `submission_ids` of Submit Sample or Submit URL.",
    )
    timeout: float = Field(
        default=1800,
        ge=0,
        allow_inf_nan=False,
        title="Wait timeout (s)",
        description="Maximum time (seconds) to wait for every submission to finish. When it runs out the action "
        "takes the `pending` branch. 0 checks once and returns at once.",
    )
    poll_interval: float = Field(
        default=10,
        gt=0,
        allow_inf_nan=False,
        title="Poll interval (s)",
        description="The amount of seconds to wait between two checks of whether the submissions have finished.",
    )

    @field_validator("submission_ids", mode="before")
    @classmethod
    def _one_or_many(cls, value: Any) -> Any:
        """A single ID is accepted as a one-item list."""
        if isinstance(value, int) and not isinstance(value, bool):
            return [value]
        return value

    @field_validator("submission_ids", mode="after")
    @classmethod
    def _distinct_and_not_empty(cls, value: list[int]) -> list[int]:
        """Duplicates are checked once. This runs after the IDs became integers, so "111" and 111 are one ID."""
        if not value:
            raise ValueError("at least one submission ID is required")
        return list(dict.fromkeys(value))


class GetSubmissionResultResults(BaseModel):
    all_finished: bool = Field(description="True when no submission is still running.")
    timed_out: bool = Field(
        default=False, description="True when the wait timed out before every submission finished."
    )
    submissions: list[Submission] = Field(default_factory=list, description="Submissions that finished without error.")
    submission_ids: list[int] = Field(
        default_factory=list,
        title="Submission IDs",
        description="IDs of the submissions that finished without error — input for Build Report.",
    )
    sample_ids: list[int] = Field(
        default_factory=list,
        title="Sample IDs",
        description="Distinct sample_ids of the submissions that finished without error — input for Build Report "
        "and the Get Sample actions.",
    )
    pending_submission_ids: list[int] = Field(
        default_factory=list,
        title="Pending Submission IDs",
        description="Submissions still running when the wait ended, or that could not be checked.",
    )
    failed_submission_ids: list[int] = Field(
        default_factory=list,
        title="Failed Submission IDs",
        description="Submissions that finished with an error.",
    )
    errors: list[dict[str, Any]] = Field(
        default_factory=list, description="Why a submission failed, or could not be checked."
    )
