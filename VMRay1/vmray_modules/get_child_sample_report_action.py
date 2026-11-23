"""GetChildSampleReport — the full VMRay report of one child sample.

The same report Build Report writes (analyses, VTIs, MITRE ATT&CK, IOCs, classifications, threat names and
screenshots, then the child's own children down to `max_recursion_depth`), but for a child picked out of a parent's
child tree — for example one Get Child Samples listed as malicious. Build Report, given the child's sample id, does
the same; this action adds the check that the child really belongs to the parent, so a wrong id fails here instead
of reporting on an unrelated sample.

The child is looked for in the parent's tree (10 levels at most) with one GET /sample/{id} per sample, nearest
levels first, and the search stops at the first match. The report is written to a JSON file on data_path and only
its path is returned, exactly like Build Report, so Render Report and Extract IOCs take it unchanged.
"""

from vmray_modules.base import VMRayAction
from vmray_modules.build_report_action import _ANALYSIS_VERDICTS, _IOC_SEVERITIES, check_filter, write_report
from vmray_modules.child_helpers import get_sample_object, walk_children
from vmray_modules.models import BuildReportArguments, BuildReportResults, GetChildSampleReportArguments

_SEARCH_DEPTH = 10  # the deepest level VMRay's child tree is followed to elsewhere in the module


class GetChildSampleReport(VMRayAction):
    name = "Get Child Sample Report"
    description = (
        "Build the full VMRay report of one child sample of a parent sample: analyses, VTIs, MITRE ATT&CK, IOCs, "
        "classifications, threat names and screenshots. Fails if the sample is not a child of the parent."
    )
    results_model = BuildReportResults

    def run(self, arguments: GetChildSampleReportArguments) -> BuildReportResults:
        check_filter("ioc_severity_filter", arguments.ioc_severity_filter, _IOC_SEVERITIES)
        check_filter("analysis_verdict_filter", arguments.analysis_verdict_filter, _ANALYSIS_VERDICTS)

        parent = get_sample_object(self.client, arguments.parent_sample_id)
        if arguments.child_sample_id == parent["sample_id"]:
            raise ValueError(f"Sample {arguments.child_sample_id} is the parent itself, not one of its children")
        if not any(
            child["sample_id"] == arguments.child_sample_id
            for child, _, _ in walk_children(self.client, parent, _SEARCH_DEPTH, {})
        ):
            raise ValueError(
                f"Sample {arguments.child_sample_id} is not a child of sample {arguments.parent_sample_id} "
                f"(searched up to {_SEARCH_DEPTH} levels)"
            )

        return write_report(
            self,
            [arguments.child_sample_id],
            BuildReportArguments(
                sample_ids=[arguments.child_sample_id],
                max_recursion_depth=arguments.max_recursion_depth,
                ioc_severity_filter=arguments.ioc_severity_filter,
                analysis_verdict_filter=arguments.analysis_verdict_filter,
                include_screenshots=arguments.include_screenshots,
            ),
            {},
        )
