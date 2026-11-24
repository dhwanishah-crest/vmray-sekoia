"""What the child-sample actions share: walking a sample's child tree (finding the sample to start from is in
sample_helpers).

VMRay lists the samples it found inside a sample (files in an archive, attachments of an email, files a URL
downloads, ...) in the parent's `sample_child_sample_ids`. Each child is a sample of its own, with its own verdict
and its own children, so the tree is walked one `GET /sample/{id}` at a time.
"""

from collections import deque
from collections.abc import Iterator
from typing import Any

from vmray_modules.build_report_action import _RECOVERABLE, _describe
from vmray_modules.client import VMRayClient
from vmray_modules.sample_helpers import get_sample_object
from vmray_modules.sample_models import ChildSample

# How severe a verdict is: the verdicts above 0 are the ones `min_verdict` can ask for. Anything else VMRay sends
# (unknown, not analysed, ...) ranks 0, so it only shows when no minimum is set.
_VERDICT_RANK = {
    "clean": 1,
    "whitelisted": 1,
    "not_suspicious": 1,
    "suspicious": 2,
    "malicious": 3,
    "blacklisted": 3,
}
MIN_VERDICTS = ("clean", "suspicious", "malicious")


def verdict_rank(verdict: Any) -> int:
    return _VERDICT_RANK.get(str(verdict or "").strip().lower(), 0)


def check_min_verdict(value: str) -> int:
    """The rank a child must reach: 0 for "return every child". A value that is not one of the allowed ones is an
    error — ignoring it would return children the playbook meant to filter out."""
    if not value:
        return 0
    if value not in MIN_VERDICTS:
        raise ValueError(f"min_verdict has no valid value: {value!r} — use 'clean', 'suspicious' or 'malicious'")
    return _VERDICT_RANK[value]


def walk_children(
    client: VMRayClient, root: dict[str, Any], max_depth: int, errors: dict[str, str]
) -> Iterator[tuple[dict[str, Any], int, int]]:
    """Every sample below `root`, nearest levels first, as (sample, depth, parent sample id).

    A sample is visited once, however many parents list it, so a tree that points back up ends instead of looping.
    A child that cannot be read lands in `errors` (`child_sample:<id>`) and the rest of the tree is still walked.
    Stops asking VMRay as soon as the caller stops iterating."""
    seen = {root["sample_id"]}
    queue: deque[tuple[dict[str, Any], int]] = deque([(root, 0)])
    while queue:
        parent, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for child_id in dict.fromkeys(parent.get("sample_child_sample_ids") or []):
            if child_id in seen:
                continue
            seen.add(child_id)
            try:
                child = get_sample_object(client, child_id)
            except _RECOVERABLE as exc:
                errors[f"child_sample:{child_id}"] = _describe(exc)
                continue
            yield child, depth + 1, parent["sample_id"]
            queue.append((child, depth + 1))


def summarise_child(sample: dict[str, Any], depth: int, parent_sample_id: int) -> ChildSample:
    """The fields of a sample object a playbook asks about; VMRay's own names are `sample_*`."""

    def text(name: str) -> str:
        value = sample.get(name)
        return value if isinstance(value, str) else ""

    score = sample.get("sample_vti_score")
    return ChildSample(
        sample_id=sample["sample_id"],
        parent_sample_id=parent_sample_id,
        depth=depth,
        name=text("sample_filename"),
        type=text("sample_type"),
        md5=text("sample_md5hash"),
        sha1=text("sample_sha1hash"),
        sha256=text("sample_sha256hash"),
        verdict=text("sample_verdict"),
        verdict_reason=text("sample_verdict_reason_description"),
        vti_score=score if isinstance(score, int) and not isinstance(score, bool) else None,
        webif_url=text("sample_webif_url"),
        child_count=len(sample.get("sample_child_sample_ids") or []),
    )
