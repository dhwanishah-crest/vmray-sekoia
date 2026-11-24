"""GetAnalysisArchive — download an analysis archive (or one file of it) from VMRay.

GET /rest/analysis/{id}/archive for the whole ZIP, or /archive/{path} for a single file such as `logs/summary.json`.
The file is saved on the playbook run's data path and returned as `files` (`[{"path": ...}]`), with its size and
SHA-256, so a later node can read it. `max_size_mb` stops an unexpectedly large archive from being loaded: the action
fails instead. Costs no quota.

`archive_path` must stay inside the archive (no absolute path, no "..").
"""

from pathlib import PurePosixPath

from vmray_modules.base import VMRayAction
from vmray_modules.sample_helpers import save_file
from vmray_modules.sample_models import GetAnalysisArchiveArguments, GetAnalysisArchiveResults


class GetAnalysisArchive(VMRayAction):
    name = "Get Analysis Archive"
    description = (
        "Download the archive of a VMRay analysis (or one file of it) into the playbook run's storage — costs no "
        "quota."
    )
    results_model = GetAnalysisArchiveResults

    def run(self, arguments: GetAnalysisArchiveArguments) -> GetAnalysisArchiveResults:
        archive_path = arguments.archive_path.replace("\\", "/")
        relative = PurePosixPath(archive_path)
        if archive_path and (relative.is_absolute() or ".." in relative.parts):
            raise ValueError(f"archive_path must be a path inside the archive: {arguments.archive_path!r}")

        content = self.client.download_analysis_archive(
            arguments.analysis_id, archive_path or None, arguments.max_size_mb * 1024 * 1024
        )
        name = relative.name if archive_path else "archive.zip"
        filename, digest = save_file(self, f"vmray-analysis-{arguments.analysis_id}", name, content)
        return GetAnalysisArchiveResults(
            files=[{"path": filename}], file_name=filename, size=len(content), sha256=digest
        )
