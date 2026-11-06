"""Build the schema-shaped incident analysis response."""

from typing import Dict, List, Mapping, Sequence


def build_report(
    request_id: str,
    summary: str,
    iocs: Sequence[Mapping[str, object]],
    behaviors: Sequence[Mapping[str, object]],
    severity: Mapping[str, object],
    root_cause_hypotheses: Sequence[Mapping[str, object]],
    investigation_steps: Sequence[Mapping[str, object]],
    containment_recommendations: Sequence[Mapping[str, object]],
    *,
    status: str = "complete",
    limitations: Sequence[str] = (),
) -> Dict[str, object]:
    """Assemble a JSON-compatible report; containment remains advisory."""
    raise NotImplementedError