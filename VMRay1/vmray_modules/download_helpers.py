"""Download a file over http(s) for DownloadFile: public hosts only, a size cap, and every redirect re-checked."""

import ipaddress
import re
import socket
from urllib.parse import unquote, urljoin, urlparse

import requests

MAX_REDIRECTS = 5
CHUNK_SIZE = 64 * 1024
USER_AGENT = "Sekoia-VMRay-DownloadFile"


class DownloadError(ValueError):
    """The file cannot be downloaded; the message is shown on the playbook node."""


def check_public_url(url: str) -> None:
    """Refuse anything but http(s) to a host whose addresses are all public, so the action cannot be used to reach
    internal services or a cloud metadata endpoint."""
    parts = urlparse(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise DownloadError(f"Only http(s) URLs can be downloaded: {url!r}")
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80))
    except socket.gaierror as exc:
        raise DownloadError(f"Cannot resolve host {parts.hostname!r}: {exc}") from exc
    for info in infos:
        if not ipaddress.ip_address(str(info[4][0]).split("%")[0]).is_global:
            raise DownloadError(f"{parts.hostname!r} resolves to a non-public address, refusing to download from it")


def safe_file_name(response: requests.Response, url: str) -> str:
    """The name from Content-Disposition, else the last segment of the URL, reduced to safe characters."""
    match = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', response.headers.get("Content-Disposition", ""))
    name = unquote(match.group(1)) if match else unquote(urlparse(url).path.rsplit("/", 1)[-1])
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name).lstrip(".")[:100]
    return name or "download.bin"


def fetch_file(url: str, max_bytes: int, timeout: float) -> tuple[bytes, str]:
    """The bytes and the file name at `url`. Redirects are followed by hand, up to MAX_REDIRECTS, each one checked."""
    for _ in range(MAX_REDIRECTS + 1):
        check_public_url(url)
        try:
            response = requests.get(
                url, stream=True, allow_redirects=False, timeout=timeout, headers={"User-Agent": USER_AGENT}
            )
        except requests.RequestException as exc:
            raise DownloadError(f"Download failed: {exc}") from exc
        with response:
            if response.is_redirect or response.is_permanent_redirect:
                location = response.headers.get("Location")
                if not location:
                    raise DownloadError("Redirect without a Location header")
                url = urljoin(url, location)
                continue
            if response.status_code != 200:
                raise DownloadError(f"Download failed: HTTP {response.status_code}")
            content = bytearray()
            for chunk in response.iter_content(CHUNK_SIZE):
                content += chunk
                if len(content) > max_bytes:
                    raise DownloadError(f"The file is larger than the {max_bytes // (1024 * 1024)} MB limit")
            if not content:
                raise DownloadError("The downloaded file is empty")
            return bytes(content), safe_file_name(response, url)
    raise DownloadError(f"More than {MAX_REDIRECTS} redirects")
