"""Build `nested_multi_child.zip`, the archive the "Test: Download and scan an archive" playbook downloads.

A zip inside a zip inside a zip, with several files at every level, so VMRay finds several child samples at several
depths (Get Child Samples, Get Child Sample Report, the child tree of Build Report). Every file is harmless text: no
malware and no EICAR string, so no antivirus has a reason to touch the repository. The archive is deterministic (fixed
timestamps), so running this script again gives the same bytes.

    python build_nested_archive.py
"""

import io
import zipfile
from pathlib import Path

HERE = Path(__file__).parent
OUTPUT = HERE / "nested_multi_child.zip"
STAMP = (2026, 1, 1, 0, 0, 0)

LEVEL_2 = {
    "c.txt": b"Level 2 file c: harmless text.\r\n",
    "d.js": b"// Level 2 file d: a harmless script that does nothing.\r\nvar x = 1;\r\n",
}
LEVEL_1 = {
    "a.txt": b"Level 1 file a: harmless text.\r\n",
    "run.cmd": b"@echo off\r\necho level 1: a harmless test file\r\n",
}
OUTER = {
    "README.txt": b"Harmless nested test archive for the Sekoia VMRay1 integration: zip in zip in zip, several files "
    b"at each level.\r\n",
    "hello.bat": b"@echo off\r\necho hello from a harmless test file\r\n",
    "hello.ps1": b"Write-Host 'hello from a harmless test file'\r\n",
    "index.html": b"<html><body><h1>Harmless test page</h1></body></html>\r\n",
}


def make_zip(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            info = zipfile.ZipInfo(name, date_time=STAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, content)
    return buffer.getvalue()


def build() -> bytes:
    level_2 = make_zip(LEVEL_2)
    level_1 = make_zip({**LEVEL_1, "level2.zip": level_2})
    return make_zip({**OUTER, "level1.zip": level_1})


if __name__ == "__main__":
    OUTPUT.write_bytes(build())
    print(f"wrote {OUTPUT} ({OUTPUT.stat().st_size} bytes)")
