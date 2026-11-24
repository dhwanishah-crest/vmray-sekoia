"""GetChildSamples — the samples VMRay found inside a sample.

Starts from a sample (or the sample of a submission) and walks its `sample_child_sample_ids` down to `max_depth`
levels, one GET /sample/{id} per child. Each child comes back with its parent, depth, name, type, hashes, verdict,
VTI score and console link. `min_verdict` keeps only the children that are at least that severe; a child that is
left out is still searched for children of its own — a clean archive can hold a malicious file.

Takes the `has_children` branch when at least one child is listed and `no_children` otherwise, so a playbook can skip
the rest. Costs no quota. A child VMRay cannot return lands in `errors` and the others are still listed.
"""

from vmray_modules.base import VMRayAction
from vmray_modules.child_helpers import (
    check_min_verdict,
    summarise_child,
    verdict_rank,
    walk_children,
)
from vmray_modules.sample_helpers import get_sample_object, resolve_sample_id
from vmray_modules.sample_models import ChildSample, GetChildSamplesArguments, GetChildSamplesResults


class GetChildSamples(VMRayAction):
    name = "Get Child Samples"
    description = (
        "List the child samples VMRay found inside a sample (files in an archive or email, files a URL downloaded, "
        "...), with their verdict, hashes and VTI score — costs no quota."
    )
    results_model = GetChildSamplesResults

    def run(self, arguments: GetChildSamplesArguments) -> GetChildSamplesResults:
        minimum = check_min_verdict(arguments.min_verdict)
        sample_id = resolve_sample_id(self.client, arguments.sample_id, arguments.submission_id)
        root = get_sample_object(self.client, sample_id)

        errors: dict[str, str] = {}
        children: list[ChildSample] = []
        total = 0
        for child, depth, parent_sample_id in walk_children(self.client, root, arguments.max_depth, errors):
            total += 1
            if verdict_rank(child.get("sample_verdict")) >= minimum:
                children.append(summarise_child(child, depth, parent_sample_id))

        self.set_output("has_children" if children else "no_children", True)
        return GetChildSamplesResults(
            has_children=bool(children),
            sample_id=root["sample_id"],
            child_count=len(children),
            total_child_count=total,
            sample_ids=[c.sample_id for c in children],
            children=children,
            errors=errors,
        )
