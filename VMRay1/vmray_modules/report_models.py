"""Models of the report actions: Build Report (and Get Child Sample Report, which returns the same results), Render
Report and Extract IOCs.

Field names on VMRay-sourced models follow the VMRay Platform REST API verbatim, so a field here can always be traced
straight back to the API. Types are intentionally loose (plain `str` rather than a `Literal`/enum) on any
VMRay-controlled value whose full set of possibilities was not confirmed against real response bodies (verdict,
severity, classification strings): a strict Literal would raise on an unseen-but-valid value VMRay adds later.

A report is a nested sample tree (ReportSample). Render Report and Extract IOCs take it as a plain dict.
"""

from typing import Any

from pydantic import BaseModel, Field, ValidationInfo, field_validator
from pydantic.json_schema import SkipJsonSchema

from vmray_modules.module_models import hide_empty_defaults

# --------------------------------------------------------------------------
# BuildReport
# --------------------------------------------------------------------------


class ReportSample(BaseModel):
    """One sample in a report: the full GET /sample/{id} object, plus the sub-resources
    fetched for it (`sample_analyses`, `sample_iocs`, ...), plus its child samples nested
    the same way. VMRay's own sample fields pass through untouched (extra: allow)."""

    model_config = {"extra": "allow"}

    sample_id: int
    sample_verdict: str | None = None
    sample_vti_score: int | None = None
    sample_webif_url: str | None = None
    sample_threat_names: list[str] = Field(default_factory=list, description="Sample + children, merged.")
    sample_classifications: list[str] = Field(default_factory=list, description="Sample + children, merged.")
    sample_analyses: list[dict[str, Any]] = Field(
        default_factory=list, description="Analyses of the latest submission (all analyses if none)."
    )
    sample_threat_indicators: dict[str, Any] = Field(default_factory=dict, description="GET /sample/{id}/vtis")
    sample_mitre_attack: dict[str, Any] = Field(default_factory=dict, description="GET /sample/{id}/mitre_attack")
    sample_iocs: dict[str, Any] = Field(default_factory=dict, description="GET /sample/{id}/iocs")
    sample_child_samples: list["ReportSample"] = Field(
        default_factory=list, description="Child samples, built the same way, down to max_recursion_depth."
    )
    has_screenshots: bool = Field(default=False, description="Any analysis in sample_analyses carries screenshots.")
    errors: dict[str, str] = Field(
        default_factory=dict, description="Sections of this sample that failed to load; the rest is still filled."
    )

    @field_validator(
        "sample_threat_names",
        "sample_classifications",
        "sample_analyses",
        "sample_threat_indicators",
        "sample_mitre_attack",
        "sample_iocs",
        "sample_child_samples",
        "errors",
        mode="before",
    )
    @classmethod
    def _null_is_empty(cls, value: Any, info: ValidationInfo) -> Any:
        """VMRay sends null for an empty list on some sample fields (e.g. the deprecated sample_threat_names)."""
        if value is None:
            return cls.model_fields[info.field_name or ""].get_default(call_default_factory=True)
        return value


class BuildReportArguments(BaseModel):
    model_config = {"json_schema_extra": hide_empty_defaults}

    sample_ids: list[int] | SkipJsonSchema[None] = Field(
        default=None,
        title="Sample IDs",
        description="VMRay sample IDs — e.g. the `sample_ids` of Get Samples By Hash.",
    )
    submission_ids: list[int] | SkipJsonSchema[None] = Field(
        default=None,
        title="Submission IDs",
        description="VMRay submission IDs — e.g. the `submission_ids` of Get Submission Result. Each is resolved to "
        "its sample with one GET /submission/{id}. Used when `sample_ids` is empty.",
    )
    max_recursion_depth: int = Field(
        title="Max recursion depth",
        default=10,
        ge=0,
        le=10,
        description="The maximum depth of recursive samples which will be analyzed in the report (at most 10). 0 "
        "disables recursion.",
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
        "'clean'. Leave empty to include all analyses, including those with an unknown verdict. Note: Adding all "
        "three allowed values is NOT the same as leaving empty — it still excludes analyses with unknown verdicts. A "
        "list with no valid value is an error.",
    )
    include_screenshots: bool = Field(
        title="Include screenshots",
        default=True,
        description="If set to true, the report includes the screenshots of the submitted or looked-up samples "
        "(the top-level samples only — never of their child samples).",
    )


class Report(BaseModel):
    """The full report, as written to the file behind BuildReport's `report_path`."""

    samples: list[ReportSample] = Field(default_factory=list)
    errors: dict[str, str] = Field(
        default_factory=dict,
        description="Samples that could not be fetched at all, keyed by sample_id — or by 'submission:<id>' when "
        "the submission itself could not be resolved to a sample.",
    )


class BuildReportResults(BaseModel):
    """Only a summary travels inline. The report itself — screenshots included — can be megabytes, far over
    Sekoia's limit on action arguments (SYM216), so it is written to data_path and passed on as a file."""

    report_path: str = Field(
        ...,
        description="Path (relative to data_path) of the full report JSON — give it to Render Report and "
        "Extract IOCs as `report_path`.",
    )
    sample_ids: list[int] = Field(default_factory=list, title="Sample IDs", description="Samples in the report.")
    errors: dict[str, str] = Field(
        default_factory=dict,
        description="Samples that could not be fetched at all, keyed by sample_id — or by 'submission:<id>' when "
        "the submission itself could not be resolved to a sample.",
    )


# --------------------------------------------------------------------------
# Indicators — IOCSet: the `iocs` object of GET /sample/{id}/iocs;
# Indicator: one entry for add_ioc_to_ioc_collection
# --------------------------------------------------------------------------


class IOCSet(BaseModel):
    """The `iocs` object from GET /sample/{id}/iocs. Keys per the spec's
    documented ioc_type filter values."""

    model_config = {"extra": "allow"}

    files: list[dict[str, Any]] = Field(default_factory=list)
    filenames: list[dict[str, Any]] = Field(default_factory=list)
    mutexes: list[dict[str, Any]] = Field(default_factory=list)
    registry: list[dict[str, Any]] = Field(default_factory=list)
    urls: list[dict[str, Any]] = Field(default_factory=list)
    domains: list[dict[str, Any]] = Field(default_factory=list)
    ips: list[dict[str, Any]] = Field(default_factory=list)
    emails: list[dict[str, Any]] = Field(default_factory=list)
    email_addresses: list[dict[str, Any]] = Field(default_factory=list)
    processes: list[dict[str, Any]] = Field(default_factory=list)


class Indicator(BaseModel):
    """One entry matching add_ioc_to_ioc_collection's expected shape."""

    value: str
    type: str


class ReportInput(BaseModel):
    model_config = {"json_schema_extra": hide_empty_defaults}

    report_path: str | SkipJsonSchema[None] = Field(
        default=None,
        title="Report Path",
        description="The report file written by Build Report — its `report_path` result.",
    )
    report: dict[str, Any] | SkipJsonSchema[None] = Field(
        default=None,
        title="Report (inline)",
        description="The report itself — only used when Report path is empty. Only for small reports: a report "
        "with screenshots exceeds Sekoia's size limit on action inputs.",
    )


class RenderReportArguments(ReportInput):
    max_comment_kb: int = Field(
        default=512,
        ge=16,
        title="Max comment size (KB)",
        description="Maximum size of each screenshot comment. Screenshots are split across as many comments as "
        "needed to stay under it — Sekoia rejects larger action inputs.",
    )


class RenderReportResults(BaseModel):
    content: str = Field(
        ...,
        description="The report as one alert comment (HTML inside markdown), without the screenshot images — give "
        "it to the Comment Alert action as its content.",
    )
    screenshot_comments: list[str] = Field(
        default_factory=list,
        description="The screenshots, split into comments of at most max_comment_kb each — post one comment per item "
        "(a Foreach over this list). Empty when the report has no screenshots.",
    )


class ExtractIocsArguments(ReportInput):
    ioc_severity_filter: list[str] = Field(
        default_factory=list,
        title="IOC Severity Filter",
        description="Restrict which IOC severities are extracted. Allowed values: 'malicious', 'suspicious'. "
        "Empty (the default) extracts every IOC, whatever its severity, and every child sample's own SHA256, "
        "whatever its verdict. With values set, a child sample's own SHA256 is extracted when its verdict is one "
        "of them.",
    )
    include_child_iocs: bool = Field(
        default=True,
        title="Include Child IOCs",
        description="If set to true, IOCs discovered in child samples, and each child sample's own SHA256, are "
        "extracted (in addition to root-sample IOCs). Set to false to only extract IOCs from the root sample.",
    )


class IndicatorGroup(BaseModel):
    """One add_ioc_to_ioc_collection call: its indicator_type and the values to push."""

    type: str = Field(..., description="Sekoia indicator_type: IP address, domain, url, email or hash.")
    indicators: list[str] = Field(default_factory=list, description="The indicator values of this type.")


class ExtractIocsResults(BaseModel):
    indicators: list[Indicator] = Field(
        default_factory=list,
        description="Every indicator found, typed as Add IOC to IOC Collection expects (indicator_type and value).",
    )
    indicator_groups: list[IndicatorGroup] = Field(
        default_factory=list,
        description="The same indicators grouped by type, one group per non-empty type — Add IOC to IOC Collection "
        "takes a single indicator_type per call, so a Foreach over this list pushes every type with one node.",
    )
