"""Download a file over HTTP(S): what the Download File action does, with no Sekoia in it.

The URL comes from a playbook, so it is checked before anything is sent: only http and https, and only to public
addresses. Without that, a playbook could make the runtime fetch cloud metadata or an internal service. Every redirect
is checked the same way, and the body is read in chunks and dropped as soon as it passes the size limit.

The address is resolved here to check it, and again by `requests` when it connects: a server that answers differently
the second time (DNS rebinding) is not stopped by this check.
"""

import hashlib
import ipaddress
import re
import socket
import time
from dataclasses import dataclass
from urllib.parse import unquote, urljoin, urlsplit

import requests

_MAX_REDIRECTS = 5
_CHUNK = 64 * 1024
_CONNECT_TIMEOUT = 10
_READ_TIMEOUT = 30
_REDIRECT_STATUS = (301, 302, 303, 307, 308)
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")
_DISPOSITION_NAME = re.compile(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', re.IGNORECASE)


class DownloadError(Exception):
    """The file could not be downloaded; the message says why."""


@dataclass
class Downloaded:
    content: bytes
    url: str  # the address the file finally came from, after redirects
    status_code: int
    content_type: str | None
    suggested_name: str | None  # from Content-Disposition, else from the URL path

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


def safe_name(name: str) -> str:
    """A file name made of letters, digits and `._-` only, whatever the URL or the server called it."""
    cleaned = _UNSAFE.sub("_", name.replace("\\", "/").rsplit("/", 1)[-1]).strip("._") or "download"
    return cleaned[:80]


def check_public_url(url: str) -> None:
    """Refuse anything but an http(s) URL whose host resolves only to public addresses."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise DownloadError("the URL must be an http:// or https:// address with a host name")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
        addresses = socket.getaddrinfo(parts.hostname, port, type=socket.SOCK_STREAM)
    except (ValueError, socket.gaierror) as exc:
        raise DownloadError(f"cannot resolve {parts.hostname}: {exc}") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if not ip.is_global:
            raise DownloadError(f"{parts.hostname} resolves to {ip}, which is not a public address")


def _suggested_name(url: str, content_disposition: str | None) -> str | None:
    if content_disposition and (match := _DISPOSITION_NAME.search(content_disposition)):
        return unquote(match.group(1).strip())
    last = unquote(urlsplit(url).path.rsplit("/", 1)[-1])
    return last or None


def download(url: str, max_bytes: int, timeout: float, verify_ssl: bool = True) -> Downloaded:
    """GET `url` and return the body. `timeout` is the most time, in seconds, the whole download may take."""
    deadline = time.monotonic() + timeout
    session = requests.Session()
    session.headers["User-Agent"] = "Sekoia-Test-Download"
    current = url
    for _ in range(_MAX_REDIRECTS + 1):
        check_public_url(current)
        try:
            response = session.get(
                current,
                stream=True,
                allow_redirects=False,
                verify=verify_ssl,
                timeout=(_CONNECT_TIMEOUT, min(_READ_TIMEOUT, timeout)),
            )
        except requests.RequestException as exc:
            raise DownloadError(f"could not download {current}: {type(exc).__name__}: {exc}") from exc

        with response:
            if response.status_code in _REDIRECT_STATUS and response.headers.get("Location"):
                current = urljoin(current, response.headers["Location"])
                continue
            if not 200 <= response.status_code < 300:
                raise DownloadError(f"{current} answered HTTP {response.status_code}")
            if int(response.headers.get("Content-Length") or 0) > max_bytes:
                raise DownloadError(f"the file is larger than the {max_bytes // (1024 * 1024)} MB limit")
            body = bytearray()
            try:
                for chunk in response.iter_content(_CHUNK):
                    body += chunk
                    if len(body) > max_bytes:
                        raise DownloadError(f"the file is larger than the {max_bytes // (1024 * 1024)} MB limit")
                    if time.monotonic() > deadline:
                        raise DownloadError(f"the download took longer than {timeout:g} seconds")
            except requests.RequestException as exc:
                raise DownloadError(f"the download was cut off: {type(exc).__name__}: {exc}") from exc
            if not body:
                raise DownloadError("the server returned an empty file")
            return Downloaded(
                content=bytes(body),
                url=current,
                status_code=response.status_code,
                content_type=response.headers.get("Content-Type"),
                suggested_name=_suggested_name(current, response.headers.get("Content-Disposition")),
            )
    raise DownloadError(f"more than {_MAX_REDIRECTS} redirects")
