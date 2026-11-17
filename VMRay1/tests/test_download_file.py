import hashlib
import json
import socket
from pathlib import Path

import pytest

from tests.test_integration import sekoia  # noqa: F401
from vmray_modules.download_file_action import DownloadFile
from vmray_modules.models import DownloadFileArguments, DownloadFileResults

MANIFEST = Path(__file__).parents[1] / "action_download_file.json"
URL = "https://files.example/samples/eicar.com.txt"
CONTENT = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def resolve_to(monkeypatch, address):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))],
    )


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    resolve_to(monkeypatch, "93.184.216.34")


def test_file_lands_in_the_run_storage_in_the_shape_submit_file_sample_takes(sekoia, requests_mock):  # noqa: F811
    requests_mock.get(URL, content=CONTENT)

    payload = sekoia(DownloadFile, {"url": f" {URL} "})

    results = payload["results"]
    sha256 = hashlib.sha256(CONTENT).hexdigest()
    assert results["files"] == [{"path": f"{sha256}_eicar.com.txt"}]
    assert (results["sha256"], results["size"], results["file_name"]) == (sha256, len(CONTENT), "eicar.com.txt")
    assert (sekoia.data_path / results["files"][0]["path"]).read_bytes() == CONTENT


def test_name_comes_from_content_disposition(sekoia, requests_mock):  # noqa: F811
    requests_mock.get(
        URL, content=CONTENT, headers={"Content-Disposition": 'attachment; filename="../../evil name.exe"'}
    )

    assert sekoia(DownloadFile, {"url": URL})["results"]["file_name"] == "_.._evil_name.exe"


def test_redirects_are_followed_and_checked(sekoia, requests_mock):  # noqa: F811
    requests_mock.get(URL, status_code=302, headers={"Location": "/real/file.bin"})
    requests_mock.get("https://files.example/real/file.bin", content=CONTENT)

    assert sekoia(DownloadFile, {"url": URL})["results"]["file_name"] == "file.bin"


@pytest.mark.parametrize("url", ["ftp://files.example/a", "file:///etc/passwd", "https://", "not a url"])
def test_only_http_urls(sekoia, url):  # noqa: F811
    payload = sekoia(DownloadFile, {"url": url})

    assert "http" in payload["error"].lower()
    assert "results" not in payload


@pytest.mark.parametrize("address", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1"])
def test_non_public_hosts_are_refused(sekoia, requests_mock, monkeypatch, address):  # noqa: F811
    resolve_to(monkeypatch, address)
    mocked = requests_mock.get(URL, content=CONTENT)

    payload = sekoia(DownloadFile, {"url": URL})

    assert "non-public" in payload["error"]
    assert not mocked.called


def test_a_redirect_to_an_internal_host_is_refused(sekoia, requests_mock, monkeypatch):  # noqa: F811
    requests_mock.get(URL, status_code=302, headers={"Location": "http://internal.example/secret"})
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, *a, **k: [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("10.0.0.5" if host == "internal.example" else "93.184.216.34", port),
            )
        ],
    )

    assert "non-public" in sekoia(DownloadFile, {"url": URL})["error"]


def test_too_large_empty_and_failed_downloads_give_an_error(sekoia, requests_mock):  # noqa: F811
    requests_mock.get(URL, content=b"x" * (1024 * 1024 + 1))
    assert "larger than" in sekoia(DownloadFile, {"url": URL, "max_size_mb": 1})["error"]

    requests_mock.get(URL, content=b"")
    assert "empty" in sekoia(DownloadFile, {"url": URL})["error"]

    requests_mock.get(URL, status_code=404)
    assert "HTTP 404" in sekoia(DownloadFile, {"url": URL})["error"]


def test_manifest_matches_the_models():
    manifest = json.loads(MANIFEST.read_text())

    assert manifest["docker_parameters"] == "DownloadFile"
    assert manifest["arguments"] == DownloadFileArguments.model_json_schema()
    assert manifest["results"] == DownloadFileResults.model_json_schema()
