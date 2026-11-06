"""Build the schema-shaped incident analysis response.

This module ONLY assembles a report from pre-computed inputs.
It never calls Groq, never executes actions, and never invents findings.
All input objects are copied — originals are never modified.
"""

import copy
import json
from typing import Dict, List, Mapping, Sequence

# Schema version emitted in every report.
_SCHEMA_VERSION = "1.0"


def _safe_list(value: object) -> list:
    """Return a shallow-safe list from a sequence, or [] for anything else.

    A plain Mapping, string, bytes, or non-sequence is treated as empty so the
    caller always gets an iterable without having to guard every access.
    """
    if isinstance(value, (str, bytes, bytearray, Mapping)):
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    # Accept any other Sequence (but not strings/bytes above).
    try:
        return list(value)
    except TypeError:
        return []


def _copy_item(item: object) -> object:
    """Deep-copy a single item so the caller's original is never mutated."""
    return copy.deepcopy(item)


def _copy_list(seq: object) -> list:
    """Deep-copy a sequence into a plain list, defaulting to [] for bad input."""
    return [_copy_item(item) for item in _safe_list(seq)]


def _enforce_approval(recommendations: list) -> list:
    """Return a new list where every containment dict has approval_required=True.

    Works on the already-copied list, so the original caller data is unchanged.
    Non-dict items are passed through untouched (validator will catch them).
    """
    result = []
    for rec in recommendations:
        if isinstance(rec, dict):
            # Already a copy — set the field directly.
            rec["approval_required"] = True
        result.append(rec)
    return result


def _safe_limitations(value: object) -> List[str]:
    """Normalise *limitations* to a list of strings.

    Accepts a sequence of strings, a single string, or anything falsy.
    Non-string items inside a sequence are converted with str().
    """
    if value is None:
        return []
    if isinstance(value, str):
        # A bare string is wrapped so callers passing a single sentence work.
        return [value] if value.strip() else []
    raw = _safe_list(value)
    return [str(item) for item in raw]


def build_report(
    request_id,
    summary,
    iocs,
    behaviors,
    severity,
    root_cause_hypotheses,
    investigation_steps,
    containment_recommendations,
    *,
    status: str = "complete",
    limitations: Sequence[str] = (),
) -> Dict[str, object]:
    """Assemble a JSON-compatible report; containment remains advisory.

    Every input collection is deep-copied before use, so the caller's objects
    are never mutated.  ``approval_required`` is unconditionally set to True
    on every containment recommendation.

    Args:
        request_id:                  Unique identifier for this analysis request.
        summary:                     Short evidence-based description of the incident.
        iocs:                        Sequence of IOC dicts from the extractor.
        behaviors:                   Sequence of behaviour dicts from the analyser.
        severity:                    Severity dict (level, rationale, confidence, evidence_refs).
        root_cause_hypotheses:       Sequence of hypothesis dicts from the analyser.
        investigation_steps:         Sequence of investigation-step dicts.
        containment_recommendations: Sequence of containment-recommendation dicts.
        status:                      Report status string (default ``"complete"``).
        limitations:                 Optional sequence of limitation strings.

    Returns:
        A JSON-serialisable dict following the project's incident report schema.
    """
    # --- Deep-copy all mutable inputs so originals are untouched. -----------
    iocs_copy = _copy_list(iocs)
    behaviors_copy = _copy_list(behaviors)

    # severity is a single mapping; gracefully handle None or non-mapping.
    if isinstance(severity, Mapping):
        severity_copy = _copy_item(severity)
    else:
        severity_copy = {}

    root_cause_copy = _copy_list(root_cause_hypotheses)
    steps_copy = _copy_list(investigation_steps)

    # Deep-copy containment list, then enforce approval on every entry.
    containment_copy = _copy_list(containment_recommendations)
    containment_copy = _enforce_approval(containment_copy)

    limitations_list = _safe_limitations(limitations)

    # --- Assemble report. ---------------------------------------------------
    report: Dict[str, object] = {
        # Schema metadata
        "schema_version": _SCHEMA_VERSION,
        "request_id": request_id,
        "status": status if isinstance(status, str) else "complete",
        # Findings
        "summary": summary if isinstance(summary, str) else "",
        "iocs": iocs_copy,
        "behaviors": behaviors_copy,
        "severity": severity_copy,
        "root_cause_hypotheses": root_cause_copy,
        "investigation_steps": steps_copy,
        "containment_recommendations": containment_copy,
        "limitations": limitations_list,
    }

    return report