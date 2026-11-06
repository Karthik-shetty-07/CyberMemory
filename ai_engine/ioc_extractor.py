"""Deterministically extract indicators of compromise from evidence records.

Extraction confidence describes confidence in recognizing a value, not whether
that value is malicious or benign.

Examples:
    >>> extract_iocs([{"id": "LOG-1", "message": "Peer 192.0.2.4"}])
    [{'type': 'ip_address', 'value': '192.0.2.4', 'confidence': 1.0, 'evidence_refs': ['LOG-1']}]
    >>> extract_iocs(None)
    []
"""

import ipaddress
import re
from typing import Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit, urlunsplit


_URL_PATTERN = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"']+")
_IPV4_PATTERN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_DOMAIN_PATTERN = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}\.?"
    r"(?![A-Za-z0-9_-])"
)
_HASH_PATTERNS = (
    ("SHA256", re.compile(r"(?i)(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])")),
    ("SHA1", re.compile(r"(?i)(?<![a-f0-9])[a-f0-9]{40}(?![a-f0-9])")),
    ("MD5", re.compile(r"(?i)(?<![a-f0-9])[a-f0-9]{32}(?![a-f0-9])")),
)

_STRUCTURED_FIELD_TYPES = {
    "fqdn": "hostname",
    "host": "hostname",
    "host_name": "hostname",
    "hostname": "hostname",
    "computer": "hostname",
    "computer_name": "hostname",
    "device": "hostname",
    "device_name": "hostname",
    "machine": "hostname",
    "machine_name": "hostname",
    "source_host": "hostname",
    "src_host": "hostname",
    "destination_host": "hostname",
    "dest_host": "hostname",
    "dst_host": "hostname",
    "user": "username",
    "username": "username",
    "user_name": "username",
    "account": "username",
    "account_name": "username",
    "subject_user": "username",
    "target_user": "username",
    "source_user": "username",
    "src_user": "username",
    "destination_user": "username",
    "dst_user": "username",
    "principal": "username",
    "login": "username",
    "process": "process_name",
    "process_name": "process_name",
    "processname": "process_name",
    "image": "process_name",
    "image_name": "process_name",
    "executable": "process_name",
    "executable_name": "process_name",
    "binary": "process_name",
}

# Explicit key=value log fields are strong labels, unlike guessed tokens.
_LABELED_VALUE_PATTERNS = (
    (
        "hostname",
        re.compile(
            r"(?i)\b(?:hostname|host|computer|device|machine)\s*[=:]\s*"
            r"[\"']?([^\s,;|\"'<>]+)"
        ),
    ),
    (
        "username",
        re.compile(
            r"(?i)\b(?:username|user|account|principal|login)\s*[=:]\s*"
            r"[\"']?([^\s,;|\"'<>]+)"
        ),
    ),
    (
        "process_name",
        re.compile(
            r"(?i)\b(?:process(?:_name)?|processname|image|executable)\s*[=:]\s*"
            r"[\"']?([^\s,;|\"'<>]+)"
        ),
    ),
)

_RECORD_ID_KEYS = {"id", "record_id", "event_id", "alert_id"}
_METADATA_KEYS = _RECORD_ID_KEYS | {
    "evidence_ref",
    "evidence_refs",
    "source_id",
    "timestamp",
    "time",
    "date",
}
_FILE_SUFFIXES = {"bat", "cmd", "dll", "dylib", "exe", "jar", "msi", "ps1", "py", "sys"}


def _normalize_field_name(name: object) -> str:
    """Make field-name styles such as processName comparable."""
    return re.sub(r"[^a-z0-9]+", "_", str(name).lower()).strip("_")


def _text_fields(value: object, field_name: str = "") -> List[Tuple[str, str]]:
    """Collect nested text while retaining each field name."""
    if isinstance(value, Mapping):
        fields = []
        for key, nested_value in value.items():
            normalized_name = _normalize_field_name(key)
            if normalized_name not in _METADATA_KEYS:
                fields.extend(_text_fields(nested_value, normalized_name))
        return fields

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        fields = []
        for nested_value in value:
            fields.extend(_text_fields(nested_value, field_name))
        return fields

    if isinstance(value, str):
        return [(field_name, value)]

    return []


def _evidence_reference(record: Mapping[str, object], record_index: int) -> str:
    """Use a record ID or a stable input-position fallback when it is absent."""
    for key, value in record.items():
        if _normalize_field_name(key) not in _RECORD_ID_KEYS:
            continue
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            reference = str(value).strip()
            if reference:
                return reference

    return "record:{}".format(record_index)


def _clean_named_value(value: str, ioc_type: str) -> Optional[str]:
    """Trim a labeled value and reduce executable paths to their file name."""
    cleaned = value.strip().strip(" \t\r\n\"'`;,|")
    if not cleaned:
        return None

    if ioc_type == "process_name":
        cleaned = cleaned.split(None, 1)[0].strip("\"'`")
        cleaned = cleaned.replace("\\", "/").rsplit("/", 1)[-1]

    return cleaned or None


def _canonical_value(ioc_type: str, value: str) -> str:
    """Make a comparison key that ignores case where values are case-insensitive."""
    if ioc_type in {"domain", "hostname", "username", "process_name", "hash"}:
        return value.rstrip(".").casefold()
    if ioc_type == "url":
        parsed_url = urlsplit(value)
        return urlunsplit(
            (
                parsed_url.scheme.casefold(),
                parsed_url.netloc.casefold(),
                parsed_url.path,
                parsed_url.query,
                parsed_url.fragment,
            )
        )
    return value


def extract_iocs(
    records: Sequence[Mapping[str, object]],
) -> List[Dict[str, object]]:
    """Extract common IOCs and attach each source record's ID.

    Text matches provide IPs, domains, URLs, and hashes. Hostnames, usernames,
    and process names come from named fields or explicit key=value labels.
    Repeated IOCs are returned once, with references from every matching record.

    Examples:
        >>> extract_iocs([{"id": "LOG-1", "message": "Peer 192.0.2.4"}])[0]
        {'type': 'ip_address', 'value': '192.0.2.4', 'confidence': 1.0, 'evidence_refs': ['LOG-1']}
        >>> extract_iocs(None)
        []
    """
    if isinstance(records, Mapping):
        records = [records]
    elif not isinstance(records, Sequence) or isinstance(records, (str, bytes, bytearray)):
        return []

    # Key by IOC type and normalized value so repeats collect evidence refs.
    extracted: Dict[Tuple[str, str], Dict[str, object]] = {}

    def add_ioc(ioc_type: str, value: str, evidence_ref: str) -> None:
        if ioc_type in {"domain", "hostname"}:
            value = value.rstrip(".")
        if not value:
            return

        key = (ioc_type, _canonical_value(ioc_type, value))
        ioc = extracted.get(key)
        if ioc is None:
            ioc = {
                "type": ioc_type,
                "value": value,
                "confidence": 1.0,
                "evidence_refs": [],
            }
            extracted[key] = ioc

        evidence_refs = ioc["evidence_refs"]
        if isinstance(evidence_refs, list) and evidence_ref not in evidence_refs:
            evidence_refs.append(evidence_ref)

    for record_index, record in enumerate(records):
        if not isinstance(record, Mapping):
            continue

        evidence_ref = _evidence_reference(record, record_index)
        for field_name, text in _text_fields(record):
            structured_type = _STRUCTURED_FIELD_TYPES.get(field_name)
            if structured_type:
                named_value = _clean_named_value(text, structured_type)
                if named_value:
                    add_ioc(structured_type, named_value, evidence_ref)

            url_ranges = []
            for url_match in _URL_PATTERN.finditer(text):
                url_value = url_match.group(0).rstrip(".,;:!?)]}")
                try:
                    parsed_url = urlsplit(url_value)
                    url_host = parsed_url.hostname
                    parsed_url.port
                except ValueError:
                    continue

                if parsed_url.scheme and parsed_url.netloc and url_host:
                    add_ioc("url", url_value, evidence_ref)
                    url_ranges.append(url_match.span())

            for ip_match in _IPV4_PATTERN.finditer(text):
                try:
                    address = ipaddress.ip_address(ip_match.group(0))
                except ValueError:
                    continue
                if address.version == 4:
                    add_ioc("ip_address", str(address), evidence_ref)

            # A URL is its own IOC; do not also extract its host as a domain.
            if structured_type not in {"hostname", "username", "process_name"}:
                for domain_match in _DOMAIN_PATTERN.finditer(text):
                    start, end = domain_match.span()
                    if any(start < url_end and end > url_start for url_start, url_end in url_ranges):
                        continue
                    domain = domain_match.group(0).rstrip(".")
                    suffix = domain.rsplit(".", 1)[-1].lower()
                    if suffix not in _FILE_SUFFIXES:
                        add_ioc("domain", domain.lower(), evidence_ref)

            for _, hash_pattern in _HASH_PATTERNS:
                for hash_match in hash_pattern.finditer(text):
                    add_ioc("hash", hash_match.group(0).lower(), evidence_ref)

            for ioc_type, labeled_pattern in _LABELED_VALUE_PATTERNS:
                for value_match in labeled_pattern.finditer(text):
                    named_value = _clean_named_value(value_match.group(1), ioc_type)
                    if named_value:
                        add_ioc(ioc_type, named_value, evidence_ref)

    return list(extracted.values())