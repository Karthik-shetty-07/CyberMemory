"""Validate report structure against the CyberMemory incident schema."""

import math
from typing import List, Mapping


_IOC_TYPES = {
    "ip_address",
    "domain",
    "url",
    "hash",
    "hostname",
    "username",
    "process_name",
}
_SEVERITY_LEVELS = {"critical", "high", "medium", "low", "informational"}
_BEHAVIOR_ASSESSMENTS = {"suspicious", "likely_benign", "uncertain"}
_INVESTIGATION_PRIORITIES = {"p1", "p2", "p3"}


def _is_confidence(value: object) -> bool:
    """Return whether a value is a finite numeric confidence from 0 to 1."""
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and 0 <= value <= 1
    )


def _validate_evidence_refs(
    value: object,
    location: str,
    errors: List[str],
    *,
    required: bool = True,
    allow_empty: bool = False,
) -> None:
    """Check evidence-reference formatting without claiming IDs are authentic."""
    if not isinstance(value, list):
        errors.append("{} must be a list of evidence reference strings.".format(location))
        return
    if required and not allow_empty and not value:
        errors.append("{} must contain at least one evidence reference.".format(location))
    for ref_index, reference in enumerate(value):
        if not isinstance(reference, str) or not reference.strip():
            errors.append(
                "{}[{}] must be a non-empty string.".format(location, ref_index)
            )


def _validate_confidence(value: object, location: str, errors: List[str]) -> None:
    """Append a validation error when confidence is missing or out of range."""
    if not _is_confidence(value):
        errors.append("{} must be a number between 0 and 1.".format(location))


def validate_report(report: Mapping[str, object]) -> List[str]:
    """Return human-readable validation errors without changing the report.

    Evidence references are checked for shape only. The original source IDs are
    not available to this function, so it cannot verify that a reference exists
    in the originating alert or logs.
    """
    if not isinstance(report, Mapping):
        return ["report must be a dictionary or mapping."]

    errors: List[str] = []

    if report.get("schema_version") != "1.0":
        errors.append("schema_version must be '1.0'.")

    request_id = report.get("request_id")
    if not isinstance(request_id, str) or not request_id.strip():
        errors.append("request_id must be a non-empty string.")

    status = report.get("status")
    if not isinstance(status, str) or status not in {"complete", "partial"}:
        errors.append("status must be 'complete' or 'partial'.")

    if not isinstance(report.get("summary"), str):
        errors.append("summary must be a string.")

    list_fields = (
        "iocs",
        "behaviors",
        "root_cause_hypotheses",
        "investigation_steps",
        "containment_recommendations",
        "limitations",
    )
    for field in list_fields:
        if not isinstance(report.get(field), list):
            errors.append("{} must be a list.".format(field))

    iocs = report.get("iocs")
    if isinstance(iocs, list):
        for index, ioc in enumerate(iocs):
            location = "iocs[{}]".format(index)
            if not isinstance(ioc, dict):
                errors.append("{} must be a dictionary.".format(location))
                continue
            if not isinstance(ioc.get("type"), str) or ioc.get("type") not in _IOC_TYPES:
                errors.append("{}.type is not a supported IOC type.".format(location))
            value = ioc.get("value")
            if not isinstance(value, str) or not value.strip():
                errors.append("{}.value must be a non-empty string.".format(location))
            _validate_confidence(ioc.get("confidence"), location + ".confidence", errors)
            _validate_evidence_refs(
                ioc.get("evidence_refs"), location + ".evidence_refs", errors
            )

    behaviors = report.get("behaviors")
    if isinstance(behaviors, list):
        for index, behavior in enumerate(behaviors):
            location = "behaviors[{}]".format(index)
            if not isinstance(behavior, dict):
                errors.append("{} must be a dictionary.".format(location))
                continue
            if not isinstance(behavior.get("description"), str) or not behavior.get(
                "description", ""
            ).strip():
                errors.append("{}.description must be a non-empty string.".format(location))
            if (
                not isinstance(behavior.get("assessment"), str)
                or behavior.get("assessment") not in _BEHAVIOR_ASSESSMENTS
            ):
                errors.append("{}.assessment is not a supported assessment.".format(location))
            _validate_confidence(
                behavior.get("confidence"), location + ".confidence", errors
            )
            _validate_evidence_refs(
                behavior.get("evidence_refs"), location + ".evidence_refs", errors
            )

    severity = report.get("severity")
    if not isinstance(severity, Mapping):
        errors.append("severity must be a dictionary or mapping.")
    else:
        if not isinstance(severity.get("level"), str) or severity.get("level") not in _SEVERITY_LEVELS:
            errors.append("severity.level is not a supported severity level.")
        rationale = severity.get("rationale")
        if not isinstance(rationale, str) or not rationale.strip():
            errors.append("severity.rationale must be a non-empty string.")
        _validate_confidence(
            severity.get("confidence"), "severity.confidence", errors
        )
        if "evidence_refs" in severity:
            _validate_evidence_refs(
                severity.get("evidence_refs"),
                "severity.evidence_refs",
                errors,
                required=False,
                allow_empty=True,
            )

    hypotheses = report.get("root_cause_hypotheses")
    if isinstance(hypotheses, list):
        for index, hypothesis in enumerate(hypotheses):
            location = "root_cause_hypotheses[{}]".format(index)
            if not isinstance(hypothesis, dict):
                errors.append("{} must be a dictionary.".format(location))
                continue
            for field in ("hypothesis", "validation"):
                value = hypothesis.get(field)
                if not isinstance(value, str) or not value.strip():
                    errors.append("{}.{} must be a non-empty string.".format(location, field))
            _validate_confidence(
                hypothesis.get("confidence"), location + ".confidence", errors
            )
            _validate_evidence_refs(
                hypothesis.get("evidence_refs"), location + ".evidence_refs", errors
            )

    investigation_steps = report.get("investigation_steps")
    if isinstance(investigation_steps, list):
        for index, step in enumerate(investigation_steps):
            location = "investigation_steps[{}]".format(index)
            if not isinstance(step, dict):
                errors.append("{} must be a dictionary.".format(location))
                continue
            for field in ("action", "rationale"):
                value = step.get(field)
                if not isinstance(value, str) or not value.strip():
                    errors.append("{}.{} must be a non-empty string.".format(location, field))
            if (
                not isinstance(step.get("priority"), str)
                or step.get("priority") not in _INVESTIGATION_PRIORITIES
            ):
                errors.append("{}.priority is not a supported priority.".format(location))
            if "expected_finding" in step and not isinstance(step["expected_finding"], str):
                errors.append("{}.expected_finding must be a string when present.".format(location))
            _validate_evidence_refs(
                step.get("evidence_refs"), location + ".evidence_refs", errors
            )

    recommendations = report.get("containment_recommendations")
    if isinstance(recommendations, list):
        for index, recommendation in enumerate(recommendations):
            location = "containment_recommendations[{}]".format(index)
            if not isinstance(recommendation, dict):
                errors.append("{} must be a dictionary.".format(location))
                continue
            for field in ("action", "target", "rationale", "impact"):
                value = recommendation.get(field)
                if not isinstance(value, str) or not value.strip():
                    errors.append("{}.{} must be a non-empty string.".format(location, field))
            if not isinstance(recommendation.get("reversible"), bool):
                errors.append("{}.reversible must be a boolean.".format(location))
            if recommendation.get("approval_required") is not True:
                errors.append("{}.approval_required must be exactly True.".format(location))
            _validate_evidence_refs(
                recommendation.get("evidence_refs"), location + ".evidence_refs", errors
            )

    limitations = report.get("limitations")
    if isinstance(limitations, list):
        for index, limitation in enumerate(limitations):
            if not isinstance(limitation, str):
                errors.append("limitations[{}] must be a string.".format(index))

    return errors