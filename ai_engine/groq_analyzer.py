"""Analyze current incident evidence with Groq."""

from typing import Dict, Mapping, Sequence


def analyze_with_groq(
    alert: Mapping[str, object],
    logs: Sequence[Mapping[str, object]],
    evidence_refs: Sequence[str],
) -> Dict[str, object]:
    """Return model findings grounded in current evidence references.

    The implementation will obtain credentials through the existing
    ``config.get_groq_api_key`` configuration function. Historical context
    from Hindsight is intentionally outside this interface.
    """
    raise NotImplementedError