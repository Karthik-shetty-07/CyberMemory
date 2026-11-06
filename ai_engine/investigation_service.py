"""Expose the incident-analysis workflow to the application backend."""

import re
from collections.abc import Mapping as MappingABC, Sequence as SequenceABC
from typing import Dict, Mapping, Sequence

if __package__:
    from .incident_processor import process_incident
else:
    from incident_processor import process_incident


_REPORT_LIST_FIELDS = (
    "iocs",
    "behaviors",
    "root_cause_hypotheses",
    "investigation_steps",
    "containment_recommendations",
    "limitations",
)
_SECRET_PATTERN = re.compile(
    r"(?i)\b((?:groq[_-]?)?api[_-]?key|password|passwd|secret|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|authorization)\s*([=:])\s*"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_TOKEN_PATTERN = re.compile(r"(?i)\b(?:gsk_[a-z0-9_-]+|Bearer\s+[^\s,;]+)")
_ERROR_CODE_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")


def _error(code: str, message: str) -> Dict[str, object]:
    """Return a stable, plain-dictionary error response."""
    return {"error": {"code": code, "message": message}}


def _safe_message(value: object) -> str:
    """Sanitize processor-provided text before exposing it to a caller."""
    if not isinstance(value, str) or not value.strip():
        return "Incident processing failed."

    message = value.strip()
    if "traceback" in message.lower() or re.search(r'File "[^\"]+", line \d+', message):
        return "Incident processing failed."
    message = _TOKEN_PATTERN.sub("[REDACTED]", message)
    message = _SECRET_PATTERN.sub(r"\1\2[REDACTED]", message)
    return message[:500]


def _processor_error(result: MappingABC) -> Dict[str, object]:
    """Keep useful structured processor errors while excluding unsafe fields."""
    processor_error = result.get("error")
    if not isinstance(processor_error, MappingABC):
        return _error("invalid_processor_response", "The incident processor returned a malformed error.")

    code = processor_error.get("code")
    message = processor_error.get("message")
    if not isinstance(code, str) or not _ERROR_CODE_PATTERN.fullmatch(code):
        return _error("processor_error", "The incident processor could not complete the request.")
    if not isinstance(message, str):
        return _error("processor_error", "The incident processor could not complete the request.")

    safe_error: Dict[str, object] = {
        "code": code,
        "message": _safe_message(message),
    }
    details = processor_error.get("details")
    if isinstance(details, list):
        safe_details = [
            _safe_message(detail)
            for detail in details[:20]
            if isinstance(detail, str)
        ]
        if safe_details:
            safe_error["details"] = safe_details
    return {"error": safe_error}


def _is_report_response(result: Dict[str, object]) -> bool:
    """Check only the report envelope; the processor owns full validation."""
    if result.get("schema_version") != "1.0":
        return False
    request_id = result.get("request_id")
    if not isinstance(request_id, str) or not request_id.strip():
        return False
    status = result.get("status")
    if not isinstance(status, str) or status not in {"complete", "partial"}:
        return False
    if not isinstance(result.get("summary"), str):
        return False
    if not all(isinstance(result.get(field), list) for field in _REPORT_LIST_FIELDS):
        return False
    return isinstance(result.get("severity"), MappingABC)


def submit_incident(
    alert: Mapping[str, object],
    logs: Sequence[Mapping[str, object]],
) -> Dict[str, object]:
    """Submit alert evidence to the processor and return its report or error.

    The processor owns evidence normalization, limits, IOC extraction, Groq
    analysis, report construction, and full report validation. This service
    validates only request-level types and the processor's response envelope.
    """
    if not isinstance(alert, MappingABC):
        return _error("invalid_alert", "Alert must be a mapping of evidence fields.")
    if not isinstance(logs, SequenceABC) or isinstance(logs, (str, bytes, bytearray)):
        return _error("invalid_logs", "Logs must be a sequence of evidence records.")
    if not alert and not logs:
        return _error("empty_evidence", "No alert or log evidence was supplied.")

    try:
        result = process_incident(alert, logs)
    except Exception:
        # Do not expose exception text, which may contain secrets or evidence.
        return _error("processing_error", "Incident processing could not be completed.")

    if not isinstance(result, dict):
        return _error("invalid_processor_response", "The incident processor returned an invalid response.")
    if "error" in result:
        if set(result) != {"error"}:
            return _error("invalid_processor_response", "The incident processor returned a malformed response.")
        return _processor_error(result)
    if not _is_report_response(result):
        return _error("invalid_processor_response", "The incident processor returned a malformed report.")

    # Pass successful reports through unchanged to preserve the established schema.
    return result