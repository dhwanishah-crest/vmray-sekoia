"""GetSampleIocs — the indicators of compromise VMRay found for a sample.

GET /rest/sample/{id}/iocs for a sample, or for the sample of a submission. The IOCs come back as VMRay sends them,
by category, with a count of each. `ioc_severity_filter` asks VMRay for only one severity (exactly one of
'malicious' / 'suspicious'; none or both returns both). Costs no quota.

Takes the `found` branch when VMRay returned at least one IOC and `not_found` otherwise. To push them to an IOC
collection use Extract IOCs, which takes a Build Report result.
"""

from typing import Any

from vmray_modules.base import VMRayAction
from vmray_modules.build_report_action import _IOC_SEVERITIES, check_filter, ioc_severity
from vmray_modules.sample_helpers import resolve_sample_id
from vmray_modules.sample_models import GetSampleIocsArguments, GetSampleIocsResults


def count_iocs(iocs: dict[str, Any]) -> dict[str, int]:
    """How many IOCs each category holds; a category that is not a list counts as empty."""
    return {category: len(items) if isinstance(items, list) else 0 for category, items in iocs.items()}


class GetSampleIocs(VMRayAction):
    name = "Get Sample IOCs"
    description = (
        "Get the indicators of compromise (URLs, domains, IPs, files, ...) VMRay found for a sample — costs no quota."
    )
    results_model = GetSampleIocsResults

    def run(self, arguments: GetSampleIocsArguments) -> GetSampleIocsResults:
        check_filter("ioc_severity_filter", arguments.ioc_severity_filter, _IOC_SEVERITIES)
        sample_id = resolve_sample_id(self.client, arguments.sample_id, arguments.submission_id)
        data = self.client.get_sample_iocs(sample_id, severity=ioc_severity(arguments.ioc_severity_filter))

        iocs = data.get("iocs") if isinstance(data, dict) else None
        iocs = iocs if isinstance(iocs, dict) else {}
        counts = count_iocs(iocs)
        total = sum(counts.values())

        self.set_output("found" if total else "not_found", True)
        return GetSampleIocsResults(
            found=bool(total), sample_id=sample_id, ioc_count=total, ioc_counts=counts, iocs=iocs
        )
