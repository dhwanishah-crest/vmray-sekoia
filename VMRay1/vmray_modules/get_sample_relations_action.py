"""GetSampleRelations — the relation records VMRay keeps between a sample and the samples found inside it.

GET /rest/sample_relation/sample/{id}, or /rest/sample_relation/submission/{id} for a submission. The records are
returned as VMRay sends them: the Console shows their relation type (for example "Embedded File"), and the records
are where it lives. VMRay's reference lists these endpoints but not the fields of a record, so none is renamed or
interpreted here, except that every `*sample_id` field is collected into `related_sample_ids`.

Takes the `found` branch when VMRay returned at least one relation and `not_found` otherwise. Costs no quota.
"""

import re
from typing import Any

from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.base import VMRayAction
from vmray_modules.models import GetSampleRelationsArguments, GetSampleRelationsResults

_SAMPLE_ID_FIELD = re.compile(r"sample_id$")


def related_sample_ids(relations: list[dict[str, Any]], asked_for: int | None) -> list[int]:
    """Every sample id named by a `*sample_id` field of the records, once each, in order of appearance. The sample
    asked for is left out: it is on every record of its own relations."""
    ids: dict[int, None] = {}
    for relation in relations:
        for name, value in relation.items():
            if _SAMPLE_ID_FIELD.search(name) and isinstance(value, int) and not isinstance(value, bool):
                if value != asked_for:
                    ids[value] = None
    return list(ids)


class GetSampleRelations(VMRayAction):
    name = "Get Sample Relations"
    description = (
        "List the relation records VMRay holds for a sample or a submission — how the samples found inside it "
        "(embedded files, downloaded files, ...) are linked to it. Costs no quota."
    )
    results_model = GetSampleRelationsResults

    def run(self, arguments: GetSampleRelationsArguments) -> GetSampleRelationsResults:
        if arguments.sample_id is None and arguments.submission_id is None:
            raise MissingActionArgumentError("sample_id or submission_id")
        relations = self.client.get_sample_relations(arguments.sample_id, arguments.submission_id)

        found = bool(relations)
        self.set_output("found" if found else "not_found", True)
        return GetSampleRelationsResults(
            found=found,
            relation_count=len(relations),
            relations=relations,
            related_sample_ids=related_sample_ids(relations, arguments.sample_id),
        )
