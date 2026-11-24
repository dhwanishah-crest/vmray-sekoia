"""GetSampleVtis — the VMRay Threat Identifiers (VTIs) of a sample.

GET /rest/sample/{id}/vtis for a sample, or for the sample of a submission. The identifiers come back as VMRay sends
them (`threat_indicators`); `min_score` keeps only those scored at least that. Costs no quota.

Takes the `found` branch when at least one identifier is returned and `not_found` otherwise.
"""

from typing import Any

from vmray_modules.base import VMRayAction
from vmray_modules.sample_helpers import resolve_sample_id
from vmray_modules.sample_models import GetSampleVtisArguments, GetSampleVtisResults


def score_of(indicator: dict[str, Any]) -> int | None:
    score = indicator.get("score")
    return score if isinstance(score, int) and not isinstance(score, bool) else None


class GetSampleVtis(VMRayAction):
    name = "Get Sample VTIs"
    description = (
        "Get the VMRay Threat Identifiers (VTIs) of a sample, optionally only the high-scoring ones — costs no quota."
    )
    results_model = GetSampleVtisResults

    def run(self, arguments: GetSampleVtisArguments) -> GetSampleVtisResults:
        sample_id = resolve_sample_id(self.client, arguments.sample_id, arguments.submission_id)
        data = self.client.get_sample_threat_indicators(sample_id)

        entries = data.get("threat_indicators") if isinstance(data, dict) else None
        indicators = [i for i in entries if isinstance(i, dict)] if isinstance(entries, list) else []
        # an identifier without a numeric score cannot be said to reach the minimum: it is kept only when none is set
        indicators = [i for i in indicators if arguments.min_score == 0 or (score_of(i) or 0) >= arguments.min_score]
        scores = [s for s in map(score_of, indicators) if s is not None]

        self.set_output("found" if indicators else "not_found", True)
        return GetSampleVtisResults(
            found=bool(indicators),
            sample_id=sample_id,
            vti_count=len(indicators),
            max_score=max(scores) if scores else None,
            threat_indicators=indicators,
        )
