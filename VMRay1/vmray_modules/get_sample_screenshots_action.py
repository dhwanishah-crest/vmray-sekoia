"""GetSampleScreenshots — save the screenshots VMRay took while analysing a sample.

Reads the analyses of the sample's latest submission, newest first, and for each one the screenshot list of its
analysis archive (`logs/summary.json`), then saves each screenshot as a file on the playbook run's data path and
returns the paths as `files` (`[{"path": ...}]`, the shape the other file actions take). The images are saved as VMRay
has them: nothing is embedded in the result, which would be far larger than Sekoia accepts as an action result.
Costs no quota.

Takes the `found` branch when at least one screenshot was saved and `not_found` otherwise. An analysis without a
screenshot list (VMRay answers 404, e.g. a static analysis) simply has no screenshots and is not an error; one whose
list or screenshot cannot be read is named in `errors`, and the others are still saved.
"""

import json
from pathlib import PurePosixPath
from typing import Any

from vmray_modules.base import VMRayAction
from vmray_modules.build_report_action import _RECOVERABLE, _describe
from vmray_modules.client import BadResponseError
from vmray_modules.sample_helpers import resolve_sample_id, save_file
from vmray_modules.sample_models import GetSampleScreenshotsArguments, GetSampleScreenshotsResults, ScreenshotFile


class GetSampleScreenshots(VMRayAction):
    name = "Get Sample Screenshots"
    description = (
        "Save the screenshots VMRay took while analysing a sample as files in the playbook run's storage — costs no "
        "quota."
    )
    results_model = GetSampleScreenshotsResults

    def run(self, arguments: GetSampleScreenshotsArguments) -> GetSampleScreenshotsResults:
        sample_id = resolve_sample_id(self.client, arguments.sample_id, arguments.submission_id)
        analyses = self.client.get_sample_analyses(sample_id)
        analyses = sorted(analyses, key=lambda a: a.get("analysis_created") or "", reverse=True)

        saved: list[ScreenshotFile] = []
        errors: dict[str, str] = {}
        for analysis in analyses:
            if len(saved) >= arguments.max_screenshots:
                break
            analysis_id = analysis.get("analysis_id")
            if not isinstance(analysis_id, int):
                continue
            for archive_path in self._screenshot_paths(analysis_id, errors):
                if len(saved) >= arguments.max_screenshots:
                    break
                name = PurePosixPath(archive_path).name
                try:
                    content = self.client.get_analysis_archive_file(analysis_id, archive_path)
                except _RECOVERABLE as exc:
                    errors[f"screenshot:{analysis_id}/{name}"] = _describe(exc)
                    continue
                filename, _ = save_file(self, f"vmray-screenshot-{analysis_id}", name, content)
                saved.append(ScreenshotFile(path=filename, analysis_id=analysis_id, name=name, size=len(content)))

        self.set_output("found" if saved else "not_found", True)
        return GetSampleScreenshotsResults(
            found=bool(saved),
            sample_id=sample_id,
            screenshot_count=len(saved),
            files=[{"path": s.path} for s in saved],
            screenshots=saved,
            errors=errors,
        )

    def _screenshot_paths(self, analysis_id: int, errors: dict[str, str]) -> list[str]:
        """The archive paths of one analysis's screenshots; what could not be read lands in `errors`."""
        try:
            summary: Any = json.loads(self.client.get_analysis_archive_file(analysis_id, "logs/summary.json"))
        except BadResponseError as exc:
            if exc.status_code != 404:
                errors[f"screenshots:{analysis_id}"] = f"screenshot list could not be read: {_describe(exc)}"
            return []
        except _RECOVERABLE as exc:
            errors[f"screenshots:{analysis_id}"] = f"screenshot list could not be read: {_describe(exc)}"
            return []
        entries = summary.get("screenshots") if isinstance(summary, dict) else None
        if not isinstance(entries, list):
            if entries is not None or not isinstance(summary, dict):
                errors[f"screenshots:{analysis_id}"] = "screenshot list could not be read: unexpected format"
            return []
        paths = [e.get("screenshot_archive_path") for e in entries if isinstance(e, dict)]
        inside: list[str] = []
        for path in paths:
            if not isinstance(path, str) or not path:
                continue
            relative = PurePosixPath(path.replace("\\", "/"))
            if relative.is_absolute() or ".." in relative.parts:
                # a client collapses ".." in a URL: such a path would ask VMRay for something other than the archive
                errors[f"screenshot:{analysis_id}/{path}"] = "not a path inside the analysis archive"
                continue
            inside.append(path)
        return inside
