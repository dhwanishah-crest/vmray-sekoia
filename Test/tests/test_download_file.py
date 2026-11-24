"""Download File: the action, the download logic and the checks on the URL."""

import hashlib
import importlib.util
import io
import ipaddress
import json
import socket
import zipfile
from pathlib import Path

import pytest
import requests
from pydantic import ValidationError
from sekoia_automation.action import Action

from download_modules.download_file_action import DownloadFile
from download_modules.download_helpers import DownloadError, check_public_url, safe_name
from download_modules.download_models import DownloadFileArguments, DownloadFileResults
from download_modules.module_models import DownloadModule

ROOT = Path(__file__).parents[1]
URL = "https://files.example.org/samples/eicar_com.zip"
ZIP = b"PK\x03\x04 pretend this is a zip file"
PUBLIC = "93.184.216.34"


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    """Every host name resolves to a public address, unless it is one of the private ones below."""
    answers = {"localhost": "127.0.0.1", "internal.example.org": "10.0.0.5", "metadata.example.org": "169.254.169.254"}

    def fake_getaddrinfo(host, port, *_args, **_kwargs):
        literal = host.strip("[]")
        try:
            ipaddress.ip_address(literal)  # an IP address resolves to itself, as the real resolver does
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (literal, port))]
        except ValueError:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (answers.get(host, PUBLIC), port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)


@pytest.fixture(autouse=True)
def storage(data_storage):
    return data_storage


def run(arguments):
    return DownloadFile(module=DownloadModule()).run(arguments)


# ---- the download ----------------------------------------------------------------------------------------------


def test_downloads_the_file_into_the_run_storage_in_the_files_format(requests_mock, storage):
    requests_mock.get(URL, content=ZIP, headers={"Content-Type": "application/zip"})

    result = run({"url": URL})

    assert result["files"] == [{"path": result["file_name"]}]  # what Submit Sample takes as is
    assert result["file_name"].startswith("download-") and result["file_name"].endswith("-eicar_com.zip")
    assert (Path(storage) / result["file_name"]).read_bytes() == ZIP
    assert result["size"] == len(ZIP)
    assert result["sha256"] == hashlib.sha256(ZIP).hexdigest()
    assert result["content_type"] == "application/zip"
    assert result["url"] == URL


def test_two_downloads_of_one_url_do_not_overwrite_each_other(requests_mock):
    requests_mock.get(URL, content=ZIP)

    assert run({"url": URL})["file_name"] != run({"url": URL})["file_name"]


def test_the_name_given_wins_over_the_name_in_the_url(requests_mock):
    requests_mock.get(URL, content=ZIP)

    assert run({"url": URL, "file_name": "my sample.zip"})["file_name"].endswith("-my_sample.zip")


def test_the_content_disposition_name_wins_over_the_url(requests_mock):
    requests_mock.get(URL, content=ZIP, headers={"Content-Disposition": 'attachment; filename="real-name.zip"'})

    assert run({"url": URL})["file_name"].endswith("-real-name.zip")


def test_a_name_with_path_tricks_stays_inside_the_run_storage(requests_mock, storage):
    requests_mock.get(URL, content=ZIP)

    name = run({"url": URL, "file_name": "../../etc/passwd"})["file_name"]

    assert "/" not in name and ".." not in name and name.endswith("-passwd")
    assert (Path(storage) / name).exists()


def test_a_url_without_a_file_name_still_gets_one(requests_mock):
    requests_mock.get("https://files.example.org/", content=ZIP)

    assert run({"url": "https://files.example.org/"})["file_name"].endswith("-download")


def test_the_url_is_stripped(requests_mock):
    requests_mock.get(URL, content=ZIP)

    assert run({"url": f"  {URL}  "})["url"] == URL


# ---- zip files --------------------------------------------------------------------------------------------------


def load_builder():
    spec = importlib.util.spec_from_file_location("build_nested_archive", ROOT / "samples" / "build_nested_archive.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def zip_tree(data: bytes, prefix: str = "") -> dict[str, bytes]:
    """Every file of a zip and of the zips inside it, by path: `level1.zip/level2.zip/c.txt`."""
    found = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for name in archive.namelist():
            content = archive.read(name)
            found[prefix + name] = content
            if name.endswith(".zip"):
                found.update(zip_tree(content, f"{prefix}{name}/"))
    return found


def test_a_binary_file_is_saved_byte_for_byte(requests_mock, storage):
    every_byte = bytes(range(256)) * 40
    requests_mock.get(URL, content=every_byte)

    name = run({"url": URL})["file_name"]

    assert (Path(storage) / name).read_bytes() == every_byte


def test_a_real_zip_is_saved_whole_and_can_be_opened(requests_mock, storage):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("one.txt", "first file")
        archive.writestr("two.txt", "second file")
    requests_mock.get(URL, content=buffer.getvalue(), headers={"Content-Type": "application/zip"})

    result = run({"url": URL})

    saved = (Path(storage) / result["file_name"]).read_bytes()
    assert saved == buffer.getvalue() and result["sha256"] == hashlib.sha256(saved).hexdigest()
    with zipfile.ZipFile(io.BytesIO(saved)) as archive:
        assert archive.testzip() is None and archive.namelist() == ["one.txt", "two.txt"]


def test_a_zip_sent_as_a_download_with_a_content_disposition_keeps_its_zip_name(requests_mock):
    requests_mock.get(
        "https://files.example.org/download?id=7",
        content=ZIP,
        headers={
            "Content-Type": "application/octet-stream",
            "Content-Disposition": "attachment; filename=samples.zip",
        },
    )

    assert run({"url": "https://files.example.org/download?id=7"})["file_name"].endswith("-samples.zip")


def test_the_nested_sample_archive_comes_through_with_every_child_file(requests_mock, storage):
    data = load_builder().build()
    requests_mock.get(URL, content=data, headers={"Content-Type": "application/zip"})

    saved = (Path(storage) / run({"url": URL})["file_name"]).read_bytes()

    tree = zip_tree(saved)
    assert saved == data
    # three zips deep, several files at every level
    assert {"README.txt", "hello.bat", "hello.ps1", "index.html", "level1.zip"} <= set(tree)
    assert {"level1.zip/a.txt", "level1.zip/run.cmd", "level1.zip/level2.zip"} <= set(tree)
    assert {"level1.zip/level2.zip/c.txt", "level1.zip/level2.zip/d.js"} <= set(tree)
    assert len(tree) == 10  # at most VMRay's limit of 10 recursive samples, so every child is analysed


def test_the_sample_archive_holds_nothing_an_antivirus_would_flag():
    tree = zip_tree(load_builder().build())

    assert all(b"EICAR" not in content.upper() for content in tree.values())


def test_the_committed_sample_archive_is_what_the_builder_makes():
    """The file the playbook downloads must not drift from the script that documents it."""
    assert (ROOT / "samples" / "nested_multi_child.zip").read_bytes() == load_builder().build()


# ---- redirects -------------------------------------------------------------------------------------------------


def test_a_redirect_is_followed_and_the_final_address_reported(requests_mock):
    requests_mock.get(URL, status_code=302, headers={"Location": "/mirror/eicar_com.zip"})
    requests_mock.get("https://files.example.org/mirror/eicar_com.zip", content=ZIP)

    result = run({"url": URL})

    assert result["url"] == "https://files.example.org/mirror/eicar_com.zip"
    assert result["file_name"].endswith("-eicar_com.zip")


def test_a_redirect_to_a_private_address_is_refused(requests_mock):
    requests_mock.get(URL, status_code=302, headers={"Location": "http://internal.example.org/secret"})
    internal = requests_mock.get("http://internal.example.org/secret", content=b"secret")

    with pytest.raises(DownloadError, match="not a public address"):
        run({"url": URL})
    assert internal.call_count == 0  # never even asked


def test_a_redirect_loop_ends(requests_mock):
    requests_mock.get(URL, status_code=302, headers={"Location": URL})

    with pytest.raises(DownloadError, match="redirects"):
        run({"url": URL})


# ---- what is refused --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("http://localhost/x.zip", "not a public address"),
        ("http://127.0.0.1/x.zip", "not a public address"),
        ("http://internal.example.org/x.zip", "not a public address"),
        ("http://metadata.example.org/latest/meta-data/", "not a public address"),
        ("http://[::1]/x.zip", "not a public address"),
        ("file:///etc/passwd", "http:// or https://"),
        ("ftp://files.example.org/x.zip", "http:// or https://"),
        ("files.example.org/x.zip", "http:// or https://"),
        ("http:///x.zip", "http:// or https://"),
    ],
)
def test_addresses_that_are_not_public_http_urls_are_refused_before_any_request(requests_mock, url, reason):
    with pytest.raises(DownloadError, match=reason):
        run({"url": url})
    assert requests_mock.call_count == 0


def test_a_host_that_does_not_resolve_is_reported(monkeypatch):
    def fail(*_args, **_kwargs):
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fail)

    with pytest.raises(DownloadError, match="cannot resolve"):
        check_public_url("https://nowhere.example.org/x")


def test_a_host_with_one_private_address_among_public_ones_is_refused(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda _host, port, *_a, **_k: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC, port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", port)),
        ],
    )

    with pytest.raises(DownloadError, match=r"10\.1\.2\.3"):
        check_public_url("https://mixed.example.org/x")


# ---- failures ---------------------------------------------------------------------------------------------------


def test_an_http_error_fails_the_action_with_the_status(requests_mock):
    requests_mock.get(URL, status_code=404)

    with pytest.raises(DownloadError, match="HTTP 404"):
        run({"url": URL})


def test_an_empty_file_is_refused(requests_mock):
    requests_mock.get(URL, content=b"")

    with pytest.raises(DownloadError, match="empty"):
        run({"url": URL})


def test_a_file_over_the_size_limit_is_refused_by_its_declared_size(requests_mock):
    requests_mock.get(URL, content=b"x", headers={"Content-Length": str(2 * 1024 * 1024)})

    with pytest.raises(DownloadError, match="larger than the 1 MB limit"):
        run({"url": URL, "max_size_mb": 1})


def test_a_file_over_the_size_limit_is_refused_while_it_streams(requests_mock):
    requests_mock.get(URL, content=b"x" * (2 * 1024 * 1024))  # no Content-Length to go by

    with pytest.raises(DownloadError, match="larger than the 1 MB limit"):
        run({"url": URL, "max_size_mb": 1})


def test_a_connection_error_is_reported_with_the_address(requests_mock):
    requests_mock.get(URL, exc=requests.ConnectTimeout("timed out"))

    with pytest.raises(DownloadError, match=r"could not download .*eicar_com\.zip"):
        run({"url": URL})


def test_nothing_is_written_when_the_download_fails(requests_mock, storage):
    requests_mock.get(URL, status_code=500)

    with pytest.raises(DownloadError):
        run({"url": URL})
    assert list(Path(storage).iterdir()) == []


# ---- inputs -----------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"url": ""},
        {"url": URL, "max_size_mb": 0},
        {"url": URL, "max_size_mb": 501},
        {"url": URL, "timeout": 0},
        {"url": URL, "timeout": float("nan")},
        {"url": URL, "timeout": 1801},
    ],
)
def test_invalid_inputs_are_refused_before_any_request(requests_mock, arguments):
    with pytest.raises(ValidationError):
        run(arguments)
    assert requests_mock.call_count == 0


def test_the_defaults():
    arguments = DownloadFileArguments(url=URL)

    assert (arguments.max_size_mb, arguments.timeout, arguments.verify_ssl, arguments.file_name) == (50, 120, True, "")


def test_ssl_verification_can_be_turned_off(requests_mock):
    requests_mock.get(URL, content=ZIP)

    run({"url": URL, "verify_ssl": False})

    assert requests_mock.last_request.verify is False


@pytest.mark.parametrize(
    ("given", "cleaned"),
    [
        ("eicar.zip", "eicar.zip"),
        ("a b/c d.zip", "c_d.zip"),
        ("..\\..\\x.zip", "x.zip"),
        ("", "download"),
        ("...", "download"),
    ],
)
def test_safe_name(given, cleaned):
    assert safe_name(given) == cleaned


# ---- manifest ---------------------------------------------------------------------------------------------------


def test_the_manifest_matches_the_models():
    manifest = json.loads((ROOT / "action_download_file.json").read_text(encoding="utf-8"))

    assert issubclass(DownloadFile, Action)
    assert manifest["docker_parameters"] == "DownloadFile"
    assert manifest["name"] == DownloadFile.name
    assert manifest["arguments"] == DownloadFileArguments.model_json_schema()
    assert manifest["results"] == DownloadFileResults.model_json_schema()


def test_the_module_manifest_names_the_integration():
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))

    assert manifest["name"] == "Test" and manifest["slug"] == "test"
