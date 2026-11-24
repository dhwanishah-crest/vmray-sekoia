"""GetSampleMitreAttackTechniques — the MITRE ATT&CK techniques VMRay saw a sample use.

GET /rest/sample/{id}/mitre_attack for a sample, or for the sample of a submission. The techniques come back as VMRay
sends them (`mitre_attack_techniques`). `technique_ids` lists the technique IDs found in them (a `technique_id` or
`id` field), for a playbook that only needs the IDs. Costs no quota.

Takes the `found` branch when VMRay returned at least one technique and `not_found` otherwise.
"""

from typing import Any

from vmray_modules.base import VMRayAction
from vmray_modules.sample_helpers import resolve_sample_id
from vmray_modules.sample_models import GetSampleMitreAttackTechniquesArguments, GetSampleMitreAttackTechniquesResults


def technique_ids(techniques: list[dict[str, Any]]) -> list[str]:
    """The distinct technique IDs, in order of appearance; a technique without one is skipped."""
    ids: dict[str, None] = {}
    for technique in techniques:
        value = technique.get("technique_id") or technique.get("id")
        if isinstance(value, str) and value:
            ids[value] = None
    return list(ids)


class GetSampleMitreAttackTechniques(VMRayAction):
    name = "Get Sample Mitre Attack Techniques"
    description = "Get the MITRE ATT&CK techniques VMRay observed for a sample — costs no quota."
    results_model = GetSampleMitreAttackTechniquesResults

    def run(self, arguments: GetSampleMitreAttackTechniquesArguments) -> GetSampleMitreAttackTechniquesResults:
        sample_id = resolve_sample_id(self.client, arguments.sample_id, arguments.submission_id)
        data = self.client.get_sample_mitre_attack(sample_id)

        entries = data.get("mitre_attack_techniques") if isinstance(data, dict) else None
        techniques = [t for t in entries if isinstance(t, dict)] if isinstance(entries, list) else []

        self.set_output("found" if techniques else "not_found", True)
        return GetSampleMitreAttackTechniquesResults(
            found=bool(techniques),
            sample_id=sample_id,
            technique_count=len(techniques),
            technique_ids=technique_ids(techniques),
            techniques=techniques,
        )
