"""DownloadFile — download a file from a URL into the playbook run's storage.

Built for testing: download a zip file (for example the EICAR test zip), then give the result's `files` to VMRay1's
Submit Sample. The file is saved as `download-<8 random hex>-<name>` so two downloads of one run never overwrite each
other, and it comes back as `[{"path": ...}]`, the shape SentinelOne's Get malwares from threat returns.

The URL is checked first (http or https, public addresses only, every redirect too), the body is limited to
`max_size_mb`, and a failure (HTTP error, too large, empty, cut off) fails the action with the reason.
"""

import uuid

from sekoia_automation.action import Action

from download_modules.download_helpers import download, safe_name
from download_modules.download_models import DownloadFileArguments, DownloadFileResults, FileRef
from download_modules.module_models import DownloadModule


class DownloadFile(Action):
    name = "Download File"
    description = (
        "Download a file (for example a zip) from a URL into the playbook run's storage, in the same `files` format "
        "as SentinelOne's Get malwares from threat, so it can be given to Submit Sample."
    )
    results_model = DownloadFileResults

    module: DownloadModule

    def run(self, arguments: DownloadFileArguments) -> DownloadFileResults:
        downloaded = download(
            arguments.url,
            max_bytes=arguments.max_size_mb * 1024 * 1024,
            timeout=arguments.timeout,
            verify_ssl=arguments.verify_ssl,
        )

        file_name = (
            f"download-{uuid.uuid4().hex[:8]}-{safe_name(arguments.file_name or downloaded.suggested_name or '')}"
        )
        self.data_path.joinpath(file_name).write_bytes(downloaded.content)
        return DownloadFileResults(
            files=[FileRef(path=file_name)],
            file_name=file_name,
            size=len(downloaded.content),
            sha256=downloaded.sha256,
            content_type=downloaded.content_type,
            url=downloaded.url,
        )
