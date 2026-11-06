"""Prepare current incident evidence and coordinate its analysis."""

import copy
import json
import math
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

if __package__:
    from .groq_analyzer import analyze_with_groq
    from .ioc_extractor import extract_iocs
    from .report_builder import build_report
    from .validator import validate_report
else:
    from groq_analyzer import analyze_with_groq
    from ioc_extractor import extract_iocs
    from report_builder import build_report
    from validator import validate_report


_MAX_LOG_RECORDS = 1000
_MAX_INPUT_BYTES = 500_000
_MAX_NESTING_DEPTH = 20
_ID_FIELDS = {"id", "record_id", "event_id", "alert_id"}
_REQUEST_ID_FIELDS = {"request_id", "id", "record_id", "event_id", "alert_id"}
_TIMESTAMP_FIELDS = {
    "timestamp",
    "time",
    "datetime",
    "event_time",
    "event_timestamp",
    "@timestamp",
}
_SECRET_FIELD_NAMES = {
    "api_key",
    "groq_api_key",
    "password",
    "passwd",
    "secret",
    "secret_key",
    "access_token",
    "refresh_token",
    "authorization",
    "credentials",
    "client_secret",
    "private_key",
}
_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b((?:groq[_-]?)?api[_-]?key|password|passwd|secret|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|authorization)\s*([=:])\s*"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_BEARER_TOKEN_PATTERN = re.compile(r"(?i)\bBearer\s+[^\s,;]+")


def _error(code: str, message: str) -> Dict[str, object]:
    """Create a predictable error without including untrusted input values."""
    return {"error": {"code": code, "message": message}}


def _normalize_field_name(name: str) -> str:
    """Normalize a field name only for checking known metadata fields."""
    camel_case_split = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name.strip())
    return re.sub(r"[^a-z0-9@]+", "_", camel_case_split.lower()).strip("_")


def _normalize_timestamp(value: str) -> str:
    """Normalize parseable ISO timestamps to UTC while retaining invalid text."""
    candidate = value.strip()
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        return candidate

    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc)
        return parsed.isoformat(timespec="auto").replace("+00:00", "Z")
    return parsed.isoformat(timespec="auto")


def _normalize_value(value: object, depth: int = 0, field_name: str = "") -> object:
    """Copy supported evidence values, trimming text and redacting clear secrets."""
    if depth > _MAX_NESTING_DEPTH:
        raise ValueError("maximum nesting depth exceeded")

    if isinstance(value, Mapping):
        normalized = {}
        for key, nested_value in value.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError("mapping keys must be non-empty strings")
            clean_key = key.strip()
            normalized_key = _normalize_field_name(clean_key)
            if normalized_key in _SECRET_FIELD_NAMES:
                normalized[clean_key] = "[REDACTED]"
            else:
                normalized[clean_key] = _normalize_value(
                    nested_value, depth + 1, normalized_key
                )
        return normalized

    if isinstance(value, (list, tuple)):
        return [
            _normalize_value(item, depth + 1, field_name)
            for item in value
        ]

    if isinstance(value, str):
        cleaned = value.strip()
        if field_name in _TIMESTAMP_FIELDS:
            cleaned = _normalize_timestamp(cleaned)
        cleaned = _BEARER_TOKEN_PATTERN.sub("Bearer [REDACTED]", cleaned)
        cleaned = _SECRET_ASSIGNMENT_PATTERN.sub(r"\1\2[REDACTED]", cleaned)
        return cleaned

    if value is None or isinstance(value, (bool, int)):
        return value

    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite numbers are not supported")
        return value

    if isinstance(value, datetime):
        if value.tzinfo is not None:
            return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        return value.isoformat()

    if isinstance(value, bytes):
        try:
            return value.decode("utf-8").strip()
        except UnicodeDecodeError as error:
            raise ValueError("binary evidence is not valid UTF-8") from error

    raise ValueError("unsupported nested value")


def _has_content(value: object) -> bool:
    """Return whether the value contains evidence beyond an empty field or ID."""
    if isinstance(value, Mapping):
        for key, nested_value in value.items():
            if _normalize_field_name(str(key)) in _ID_FIELDS | _REQUEST_ID_FIELDS:
                continue
            if _has_content(nested_value):
                return True
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(_has_content(item) for item in value)
    return value is not None


def _get_identifier(record: Mapping[str, object]) -> Optional[str]:
    """Read an existing non-empty string or integer evidence ID."""
    for key, value in record.items():
        if _normalize_field_name(key) not in _ID_FIELDS:
            continue
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            identifier = str(value).strip()
            if identifier:
                return identifier
    return None


def _canonical_record(record: Mapping[str, object]) -> str:
    """Serialize a normalized record consistently for safe exact deduplication."""
    return json.dumps(record, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _input_exceeds_limit(value: object) -> bool:
    """Estimate nested input size before copying large strings or collections."""
    total_bytes = 0
    pending = [(value, 0)]
    while pending:
        current, depth = pending.pop()
        if depth > _MAX_NESTING_DEPTH:
            continue
        if isinstance(current, str):
            total_bytes += len(current.encode("utf-8"))
        elif isinstance(current, bytes):
            total_bytes += len(current)
        elif isinstance(current, Mapping):
            for key, nested_value in current.items():
                if isinstance(key, str):
                    total_bytes += len(key.encode("utf-8"))
                pending.append((nested_value, depth + 1))
        elif isinstance(current, Sequence) and not isinstance(
            current, (str, bytes, bytearray)
        ):
            pending.extend((item, depth + 1) for item in current)
        if total_bytes > _MAX_INPUT_BYTES:
            return True
    return False


def _prepare_alert(alert: Mapping[str, object]) -> Tuple[Dict[str, object], str]:
    """Normalize the alert and ensure downstream code can reference its ID."""
    normalized_alert = _normalize_value(alert)
    if not isinstance(normalized_alert, dict) or not _has_content(normalized_alert):
        raise ValueError("alert contains no usable evidence")

    alert_ref = _get_identifier(normalized_alert) or "alert:0"
    normalized_alert["id"] = alert_ref
    return normalized_alert, alert_ref


def _prepare_logs(
    logs: Sequence[Mapping[str, object]],
) -> Tuple[List[Dict[str, object]], List[str], List[str]]:
    """Normalize usable logs, add stable IDs, and remove only safe duplicates."""
    normalized_logs = []
    evidence_refs = []
    limitations = []
    seen_exact_records = set()
    seen_unidentified_records = set()
    seen_ids = {}

    for record_index, raw_record in enumerate(logs):
        if not isinstance(raw_record, Mapping):
            limitations.append(
                "Malformed log entry at index {} was excluded.".format(record_index)
            )
            continue

        try:
            record = _normalize_value(raw_record)
        except ValueError:
            limitations.append(
                "Malformed log entry at index {} was excluded.".format(record_index)
            )
            continue

        if not isinstance(record, dict) or not _has_content(record):
            limitations.append(
                "Empty log entry at index {} was excluded.".format(record_index)
            )
            continue

        existing_identifier = _get_identifier(record)
        content_without_id = {
            key: value
            for key, value in record.items()
            if _normalize_field_name(key) not in _ID_FIELDS
        }
        canonical_content = _canonical_record(content_without_id)

        if existing_identifier is None and canonical_content in seen_unidentified_records:
            if "Exact duplicate log records were omitted." not in limitations:
                limitations.append("Exact duplicate log records were omitted.")
            continue

        identifier = existing_identifier or "record:{}".format(record_index)
        record["id"] = identifier
        canonical_record = _canonical_record(record)

        if canonical_record in seen_exact_records:
            if "Exact duplicate log records were omitted." not in limitations:
                limitations.append("Exact duplicate log records were omitted.")
            continue

        previous_record = seen_ids.get(identifier)
        if previous_record is not None:
            if previous_record == canonical_record:
                continue
            raise ValueError("conflicting records use the same evidence ID")

        seen_exact_records.add(canonical_record)
        if existing_identifier is None:
            seen_unidentified_records.add(canonical_content)
        seen_ids[identifier] = canonical_record
        normalized_logs.append(record)
        evidence_refs.append(identifier)

    return normalized_logs, evidence_refs, limitations


def process_incident(
    alert: Mapping[str, object],
    logs: Sequence[Mapping[str, object]],
) -> Dict[str, object]:
    """Normalize evidence, run deterministic IOC extraction and AI analysis.

    A non-empty alert can be analyzed without logs; that condition is called out
    in report limitations. Malformed log rows are excluded and noted. Errors
    are returned as ``{"error": {"code": ..., "message": ...}}`` objects.
    """
    if not isinstance(alert, Mapping):
        return _error("invalid_alert", "Alert must be a mapping of evidence fields.")
    if not isinstance(logs, Sequence) or isinstance(logs, (str, bytes, bytearray)):
        return _error("invalid_logs", "Logs must be a sequence of evidence records.")
    if len(logs) > _MAX_LOG_RECORDS:
        return _error("input_too_large", "The log record count exceeds the processing limit.")
    if _input_exceeds_limit((alert, logs)):
        return _error("input_too_large", "The input evidence exceeds the processing limit.")

    try:
        normalized_alert, alert_ref = _prepare_alert(alert)
    except ValueError:
        return _error("invalid_alert", "Alert is empty or contains unsupported data.")

    try:
        normalized_logs, log_refs, limitations = _prepare_logs(logs)
    except ValueError:
        return _error("invalid_logs", "Logs contain conflicting evidence IDs.")

    try:
        evidence_json = json.dumps(
            {"alert": normalized_alert, "logs": normalized_logs},
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        return _error("invalid_input", "Alert or log evidence could not be encoded safely.")

    if len(evidence_json.encode("utf-8")) > _MAX_INPUT_BYTES:
        return _error("input_too_large", "The normalized evidence exceeds the processing limit.")

    if not _has_content(normalized_alert) and not normalized_logs:
        return _error("empty_evidence", "No usable alert or log evidence was supplied.")
    if not normalized_logs:
        limitations.append("No usable log records were supplied; analysis is based on the alert.")

    evidence_refs = [alert_ref] + log_refs
    evidence_records = [normalized_alert] + normalized_logs

    try:
        iocs = extract_iocs(evidence_records)
        analysis = analyze_with_groq(normalized_alert, normalized_logs, evidence_refs)
    except Exception:
        return _error("processing_error", "Incident analysis could not be completed.")

    if not isinstance(analysis, Mapping):
        return _error("invalid_analysis", "The analyzer returned an invalid response.")
    if "error" in analysis:
        return copy.deepcopy(dict(analysis))

    analysis_limitations = analysis.get("limitations", [])
    if isinstance(analysis_limitations, list):
        for limitation in analysis_limitations:
            if isinstance(limitation, str) and limitation not in limitations:
                limitations.append(limitation)

    request_id_value = next(
        (
            value.strip()
            for key, value in normalized_alert.items()
            if _normalize_field_name(key) in _REQUEST_ID_FIELDS
            and isinstance(value, str)
            and value.strip()
        ),
        alert_ref,
    )

    try:
        report = build_report(
            request_id=request_id_value,
            summary=analysis.get("summary", ""),
            iocs=iocs,
            behaviors=analysis.get("behaviors", []),
            severity=analysis.get("severity", {}),
            root_cause_hypotheses=analysis.get("root_cause_hypotheses", []),
            investigation_steps=analysis.get("investigation_steps", []),
            containment_recommendations=analysis.get("containment_recommendations", []),
            status="partial" if limitations else "complete",
            limitations=limitations,
        )
        validation_errors = validate_report(report)
    except Exception:
        return _error("processing_error", "The incident report could not be assembled.")

    if validation_errors:
        return {
            "error": {
                "code": "invalid_report",
                "message": "The generated incident report failed validation.",
                "details": validation_errors,
            }
        }

    return report