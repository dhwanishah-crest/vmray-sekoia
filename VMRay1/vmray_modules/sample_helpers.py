"""What the actions that start from a VMRay sample share: finding the sample, and saving a downloaded file.

Every "Get ..." action takes a `sample_id` or, when that is empty, the `submission_id` of the submission that made
the sample (e.g. the `submission_ids` of Get Submission Result).
"""

import hashlib
import re
import uuid
from typing import Any

from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.base import VMRayAction
from vmray_modules.client import VMRayClient

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def resolve_sample_id(client: VMRayClient, sample_id: int | None, submission_id: int | None) -> int:
    """`sample_id` as given, else the sample of the submission."""
    if sample_id is not None:
        return sample_id
    if submission_id is None:
        raise MissingActionArgumentError("sample_id or submission_id")
    submission = client.get_submission(submission_id)
    resolved = submission.get("submission_sample_id") if isinstance(submission, dict) else None
    if resolved is None:
        raise ValueError(f"VMRay returned no sample for submission {submission_id}")
    return int(resolved)


def get_sample_object(client: VMRayClient, sample_id: int) -> dict[str, Any]:
    sample = client.get_sample(sample_id)
    if not isinstance(sample, dict) or "sample_id" not in sample:
        raise ValueError(f"VMRay returned an unexpected answer for sample {sample_id}")
    return sample


def safe_name(name: str) -> str:
    """A file name made of letters, digits and `._-` only, whatever VMRay or the sample called it."""
    cleaned = _UNSAFE.sub("_", name.rsplit("/", 1)[-1]).strip("._") or "file"
    return cleaned[:80]


def save_file(action: VMRayAction, prefix: str, name: str, content: bytes) -> tuple[str, str]:
    """Write `content` to the playbook run's data path as `<prefix>-<random>-<name>` and return (that file name,
    its SHA-256). The name is unique, so two actions of one run never overwrite each other's files; later nodes
    take it as `{"path": ...}`, the shape SentinelOne's Get malwares from threat returns."""
    filename = f"{prefix}-{uuid.uuid4().hex[:8]}-{safe_name(name)}"
    action.data_path.joinpath(filename).write_bytes(content)
    return filename, hashlib.sha256(content).hexdigest()
