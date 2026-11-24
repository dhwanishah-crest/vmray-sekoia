"""Models of the actions that read a sample from VMRay: Get Samples By Hash, Get Child Samples, Get Sample Relations,
Get Child Sample Report, and Get Sample IOCs / Mitre Attack Techniques / VTIs / Screenshots / Report, and Get
Analysis Archive.

Field names on VMRay-sourced models follow the VMRay Platform REST API verbatim (see models.py).
"""

from typing import Any

from pydantic import BaseModel, Field, field_validator
from pydantic.json_schema import SkipJsonSchema

from vmray_modules.models import hide_empty_defaults

# --------------------------------------------------------------------------
# GetSamplesByHash — lookup only; building the full report is a separate action
# --------------------------------------------------------------------------


class GetSamplesByHashArguments(BaseModel):
    hashes: list[str] = Field(
        ...,
        title="File hashes",
        description="List of SHA256, SHA1 or MD5 file hashes to look up in VMRay — e.g. the hashes extracted from "
        "the alert's events. Duplicates are ignored; no quota is used.",
    )

    @field_validator("hashes", mode="before")
    @classmethod
    def _one_or_many(cls, value: Any) -> Any:
        """A single hash is accepted as a one-item list, and empty values — what a playbook template yields for
        an event without that hash field — are dropped instead of failing the action."""
        if isinstance(value, str):
            value = [value]
        if isinstance(value, list):
            return [str(h) for h in value if h is not None and str(h).strip()]
        return value


class GetSamplesByHashResults(BaseModel):
    found: bool = Field(description="True when VMRay knows at least one sample for the hashes.")
    sample_ids: list[int] = Field(
        default_factory=list, title="Sample IDs", description="Distinct VMRay sample_ids matched."
    )
    samples: list[dict[str, Any]] = Field(
        default_factory=list,
        description="The matched sample objects as VMRay returns them from the lookup (verdict, score, hashes, "
        "threat names, classifications, report link) — no VTIs/IOCs/MITRE ATT&CK, those need a separate fetch.",
    )
    not_found: list[str] = Field(default_factory=list, description="Hashes VMRay has never analysed.")
    errors: dict[str, str] = Field(
        default_factory=dict, description="Per-hash failures (invalid hash or lookup error)."
    )


# --------------------------------------------------------------------------
# Child samples — GetChildSamples, GetSampleRelations, GetChildSampleReport
# --------------------------------------------------------------------------


class GetChildSamplesArguments(BaseModel):
    model_config = {"json_schema_extra": hide_empty_defaults}

    sample_id: int | SkipJsonSchema[None] = Field(
        default=None,
        title="Sample ID",
        description="VMRay ID of the parent sample — e.g. the `sample_ids` of Get Samples By Hash or Submit File "
        "Sample.",
    )
    submission_id: int | SkipJsonSchema[None] = Field(
        default=None,
        title="Submission ID",
        description="VMRay submission ID — e.g. the `submission_ids` of Submit Sample And Wait. It is resolved to its "
        "sample with one GET /submission/{id}. Used when `sample_id` is empty.",
    )
    max_depth: int = Field(
        default=10,
        ge=1,
        le=10,
        title="Max depth",
        description="How many levels of child samples to follow (at most 10): 1 lists only the direct children, "
        "2 adds their children, and so on.",
    )
    min_verdict: str = Field(
        default="",
        title="Minimum verdict",
        description="Only return children whose verdict is at least this severe. Allowed values: 'clean' (every "
        "child with a known verdict), 'suspicious' (suspicious and malicious) or 'malicious'. Leave empty to return "
        "every child. A child that does not match is left out of the list, but its own children are still searched. "
        "A value that is not one of these is an error.",
    )

    @field_validator("min_verdict", mode="before")
    @classmethod
    def _normalise_verdict(cls, value: Any) -> Any:
        return value.strip().lower() if isinstance(value, str) else value


class ChildSample(BaseModel):
    sample_id: int = Field(title="Sample ID", description="VMRay sample ID of the child.")
    parent_sample_id: int = Field(
        title="Parent Sample ID", description="The sample this child was found in (one level up)."
    )
    depth: int = Field(description="1 for a direct child of the sample asked for, 2 for a child of a child, ...")
    name: str = Field(default="", description="The child's file name.")
    type: str = Field(default="", description="VMRay's file type of the child, e.g. 'Windows Exe (x86-64)'.")
    md5: str = Field(default="", title="MD5")
    sha1: str = Field(default="", title="SHA-1")
    sha256: str = Field(default="", title="SHA-256")
    verdict: str = Field(default="", description="VMRay's verdict for the child, e.g. 'malicious'. Empty if unknown.")
    verdict_reason: str = Field(default="", description="Why VMRay gave that verdict.")
    vti_score: int | None = Field(default=None, title="VTI score", description="VMRay Threat Identifier score, 0-100.")
    webif_url: str = Field(default="", title="Web link", description="The child's page in the VMRay console.")
    child_count: int = Field(default=0, description="How many samples VMRay found inside this child.")


class GetChildSamplesResults(BaseModel):
    has_children: bool = Field(description="True when at least one child matches (after `min_verdict`).")
    sample_id: int = Field(title="Sample ID", description="The parent sample the children were looked up for.")
    child_count: int = Field(default=0, description="How many children are listed (after `min_verdict`).")
    total_child_count: int = Field(
        default=0, description="How many children were found in the tree before `min_verdict` was applied."
    )
    sample_ids: list[int] = Field(
        default_factory=list,
        title="Sample IDs",
        description="The listed children's sample IDs — input for Build Report.",
    )
    children: list[ChildSample] = Field(
        default_factory=list, description="The children, nearest levels first, each with its parent and depth."
    )
    errors: dict[str, str] = Field(
        default_factory=dict, description="Children that could not be read, by `child_sample:<id>`."
    )


class GetSampleRelationsArguments(BaseModel):
    model_config = {"json_schema_extra": hide_empty_defaults}

    sample_id: int | SkipJsonSchema[None] = Field(
        default=None,
        title="Sample ID",
        description="VMRay sample ID: the relations that involve this sample are returned "
        "(GET /rest/sample_relation/sample/{id}).",
    )
    submission_id: int | SkipJsonSchema[None] = Field(
        default=None,
        title="Submission ID",
        description="VMRay submission ID: the relations created by this submission are returned "
        "(GET /rest/sample_relation/submission/{id}). Used when `sample_id` is empty.",
    )


class GetSampleRelationsResults(BaseModel):
    found: bool = Field(description="True when VMRay returned at least one relation.")
    relation_count: int = Field(default=0, description="How many relation records VMRay returned.")
    relations: list[dict[str, Any]] = Field(
        default_factory=list,
        description="The relation records exactly as VMRay returns them (relation type, the samples and the "
        "submission it links).",
    )
    related_sample_ids: list[int] = Field(
        default_factory=list,
        title="Related sample IDs",
        description="Every other sample named in the records, taken from their `*sample_id` fields (the sample "
        "asked for is left out).",
    )


class GetChildSampleReportArguments(BaseModel):
    parent_sample_id: int = Field(
        ...,
        title="Parent Sample ID",
        description="VMRay ID of the sample the child was found in — e.g. `sample_id` of Get Child Samples.",
    )
    child_sample_id: int = Field(
        ...,
        title="Child Sample ID",
        description="VMRay ID of the child to build the report for — e.g. one of the `sample_ids` of Get Child "
        "Samples. It must be somewhere in the parent's child tree (up to 10 levels), else the action fails.",
    )
    max_recursion_depth: int = Field(
        title="Max recursion depth",
        default=10,
        ge=0,
        le=10,
        description="The maximum depth of recursive samples of the child which will be analyzed in the report (at "
        "most 10). 0 disables recursion.",
    )
    ioc_severity_filter: list[str] = Field(
        title="IOC severity filter",
        default_factory=list,
        description="Restrict which IOC severities are fetched from VMRay. Allowed values: 'malicious', "
        "'suspicious'. Add exactly one to filter server-side; leave empty (or add both) to fetch both severities. A "
        "list with no valid value is an error.",
    )
    analysis_verdict_filter: list[str] = Field(
        title="Analysis verdict filter",
        default_factory=list,
        description="Analysis verdicts to include in the report. Allowed values: 'malicious', 'suspicious', "
        "'clean'. Leave empty to include all analyses, including those with an unknown verdict. A list with no "
        "valid value is an error.",
    )
    include_screenshots: bool = Field(
        title="Include screenshots",
        default=True,
        description="If set to true, the report includes the screenshots of the child sample.",
    )


# --------------------------------------------------------------------------
# Get Sample IOCs / Mitre Attack Techniques / VTIs / Screenshots / Report and Get Analysis Archive
# --------------------------------------------------------------------------


class SampleRefArguments(BaseModel):
    """The sample the Get Sample ... actions read: its ID, or the submission that made it."""

    model_config = {"json_schema_extra": hide_empty_defaults}

    sample_id: int | SkipJsonSchema[None] = Field(
        default=None,
        title="Sample ID",
        description="VMRay sample ID — e.g. the `sample_ids` of Get Submission Result or Get Samples By Hash.",
    )
    submission_id: int | SkipJsonSchema[None] = Field(
        default=None,
        title="Submission ID",
        description="VMRay submission ID — e.g. the `submission_ids` of Submit Sample. It is resolved to its sample "
        "with one GET /submission/{id}. Used when `sample_id` is empty.",
    )


class GetSampleIocsArguments(SampleRefArguments):
    ioc_severity_filter: list[str] = Field(
        title="IOC severity filter",
        default_factory=list,
        description="Restrict which IOC severities are fetched from VMRay. Allowed values: 'malicious', "
        "'suspicious'. Add exactly one to filter server-side; leave empty (or add both) to fetch both severities. A "
        "list with no valid value is an error.",
    )


class GetSampleIocsResults(BaseModel):
    found: bool = Field(description="True when VMRay returned at least one IOC.")
    sample_id: int = Field(title="Sample ID", description="The sample the data belongs to.")
    ioc_count: int = Field(default=0, description="How many IOCs there are in all categories.")
    ioc_counts: dict[str, int] = Field(default_factory=dict, description="How many IOCs there are per category.")
    iocs: dict[str, Any] = Field(
        default_factory=dict,
        description="The IOCs as VMRay returns them, by category (urls, domains, ips, files, mutexes, ...).",
    )


class GetSampleMitreAttackTechniquesArguments(SampleRefArguments):
    pass


class GetSampleMitreAttackTechniquesResults(BaseModel):
    found: bool = Field(description="True when VMRay returned at least one technique.")
    sample_id: int = Field(title="Sample ID", description="The sample the data belongs to.")
    technique_count: int = Field(default=0, description="How many techniques VMRay returned.")
    technique_ids: list[str] = Field(
        default_factory=list,
        title="Technique IDs",
        description="The ATT&CK technique IDs found in the techniques (e.g. T1055), in order.",
    )
    techniques: list[dict[str, Any]] = Field(
        default_factory=list, description="The techniques exactly as VMRay returns them."
    )


class GetSampleVtisArguments(SampleRefArguments):
    min_score: int = Field(
        default=0,
        ge=0,
        le=5,
        title="Minimum score",
        description="Only return the threat identifiers whose score is at least this (VMRay scores them 1 to 5). "
        "0 returns every identifier.",
    )


class GetSampleVtisResults(BaseModel):
    found: bool = Field(description="True when at least one VMRay Threat Identifier is returned.")
    sample_id: int = Field(title="Sample ID", description="The sample the data belongs to.")
    vti_count: int = Field(
        default=0, title="VTI count", description="How many threat identifiers are returned (after `min_score`)."
    )
    max_score: int | None = Field(default=None, description="The highest score among the returned identifiers.")
    threat_indicators: list[dict[str, Any]] = Field(
        default_factory=list, description="The VMRay Threat Identifiers exactly as VMRay returns them."
    )


class GetSampleScreenshotsArguments(SampleRefArguments):
    max_screenshots: int = Field(
        default=20,
        ge=1,
        le=200,
        title="Max screenshots",
        description="The most screenshots to save, taking the newest analyses first.",
    )


class ScreenshotFile(BaseModel):
    path: str = Field(description="The screenshot's file in the playbook run's storage.")
    analysis_id: int = Field(title="Analysis ID")
    name: str = Field(description="The screenshot's name in the analysis archive.")
    size: int = Field(description="Size in bytes.")


class GetSampleScreenshotsResults(BaseModel):
    found: bool = Field(description="True when at least one screenshot was saved.")
    sample_id: int = Field(title="Sample ID", description="The sample the data belongs to.")
    screenshot_count: int = Field(default=0, description="How many screenshots were saved.")
    files: list[dict[str, str]] = Field(
        default_factory=list,
        description='The saved screenshots as {"path": ...}, the shape the file actions take.',
    )
    screenshots: list[ScreenshotFile] = Field(
        default_factory=list, description="The saved screenshots with their analysis and size."
    )
    errors: dict[str, str] = Field(default_factory=dict, description="Screenshots or analyses that could not be read.")


class GetAnalysisArchiveArguments(BaseModel):
    analysis_id: int = Field(
        ...,
        title="Analysis ID",
        description="VMRay analysis ID — e.g. the `analysis_id` of an analysis in Build Report's report, or of a "
        "screenshot of Get Sample Screenshots.",
    )
    archive_path: str = Field(
        default="",
        title="Archive path",
        description="One file of the archive, such as 'logs/summary.json', instead of the whole ZIP. Leave empty for "
        "the whole archive. A path that is absolute or contains '..' is an error.",
    )
    max_size_mb: int = Field(
        default=64,
        ge=1,
        le=512,
        title="Max size (MB)",
        description="The largest answer accepted, in megabytes; a bigger one fails the action instead of filling "
        "the playbook run's storage.",
    )

    @field_validator("archive_path", mode="before")
    @classmethod
    def _strip_path(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class SavedFileResults(BaseModel):
    files: list[dict[str, str]] = Field(
        default_factory=list, description='The saved file as {"path": ...} in the playbook run\'s storage.'
    )
    file_name: str = Field(default="", title="File Name", description="Name of the saved file.")
    size: int = Field(default=0, description="Size of the file in bytes.")
    sha256: str = Field(default="", title="SHA-256", description="SHA-256 of the saved file.")


class GetAnalysisArchiveResults(SavedFileResults):
    pass


class GetSampleReportArguments(SampleRefArguments):
    max_size_mb: int = Field(
        default=64,
        ge=1,
        le=512,
        title="Max size (MB)",
        description="The largest report accepted, in megabytes; a bigger one fails the action.",
    )


class GetSampleReportResults(SavedFileResults):
    sample_id: int = Field(default=0, title="Sample ID", description="The sample the report belongs to.")
    content_type: str = Field(default="", description="The Content-Type VMRay answered with, e.g. 'application/pdf'.")
