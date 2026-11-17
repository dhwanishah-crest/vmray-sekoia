"""DownloadFile — fetch a file from a URL into the playbook run's data storage.

The output has the shape Submit File Sample takes (`files`: a list of {"path": ...}), so a playbook can scan any
file reachable by URL without an EDR in the chain.
"""

import hashlib

from vmray_modules.base import VMRayAction
from vmray_modules.download_helpers import fetch_file
from vmray_modules.models import DownloadFileArguments, DownloadFileResults


class DownloadFile(VMRayAction):
    name = "Download File"
    description = "Download a file from an http(s) URL into the playbook run's storage, ready for Submit File Sample."
    results_model = DownloadFileResults

    def run(self, arguments: DownloadFileArguments) -> DownloadFileResults:
        content, file_name = fetch_file(arguments.url, arguments.max_size_mb * 1024 * 1024, arguments.timeout)
        sha256 = hashlib.sha256(content).hexdigest()
        path = f"{sha256}_{file_name}"
        self.data_path.joinpath(path).write_bytes(content)
        self.log(message=f"Downloaded {file_name} ({len(content)} bytes, sha256 {sha256})", level="info")
        return DownloadFileResults(files=[{"path": path}], file_name=file_name, sha256=sha256, size=len(content))
