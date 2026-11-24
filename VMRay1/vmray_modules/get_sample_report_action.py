"""GetSampleReport — download the report VMRay generates for a sample.

GET /rest/sample/{id}/report for a sample, or for the sample of a submission. VMRay's API reference lists the endpoint
but not what it answers with, so the answer is saved as received on the playbook run's data path and its
`content_type` is returned, with the file (`files`, `[{"path": ...}]`), its size and SHA-256. The file gets an
extension from the content type (.pdf, .json, .zip, .html, else .bin). `max_size_mb` makes an unexpectedly large answer
fail the action instead of filling the storage. Costs no quota.

This is VMRay's own report. To build the report Sekoia comments on an alert, use Build Report and Render Report.
"""

from vmray_modules.base import VMRayAction
from vmray_modules.sample_helpers import resolve_sample_id, save_file
from vmray_modules.sample_models import GetSampleReportArguments, GetSampleReportResults

_EXTENSIONS = {
    "application/pdf": ".pdf",
    "application/json": ".json",
    "application/zip": ".zip",
    "text/html": ".html",
}


def extension_for(content_type: str) -> str:
    return _EXTENSIONS.get(content_type.split(";")[0].strip().lower(), ".bin")


class GetSampleReport(VMRayAction):
    name = "Get Sample Report"
    description = "Download the report VMRay generated for a sample into the playbook run's storage — costs no quota."
    results_model = GetSampleReportResults

    def run(self, arguments: GetSampleReportArguments) -> GetSampleReportResults:
        sample_id = resolve_sample_id(self.client, arguments.sample_id, arguments.submission_id)
        content, content_type = self.client.download_sample_report(sample_id, arguments.max_size_mb * 1024 * 1024)

        filename, digest = save_file(
            self, f"vmray-report-{sample_id}", f"report{extension_for(content_type)}", content
        )
        return GetSampleReportResults(
            sample_id=sample_id,
            files=[{"path": filename}],
            file_name=filename,
            size=len(content),
            sha256=digest,
            content_type=content_type,
        )
