"""
Input sanitization and file upload validation.
"""

import os
import re
from typing import Tuple, Dict, Any, Optional

ALLOWED_EXTENSIONS = {".json", ".log", ".txt", ".csv"}
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_TEXT_INPUT_LENGTH = 100_000  # 100k characters

# Dangerous executable magic signatures (hex prefixes)
DISALLOWED_MAGIC_SIGNATURES = [
    b"MZ",                # Windows PE EXE / DLL
    b"\x7fELF",           # Linux ELF binary
    b"\xfe\xed\xfa\xce",  # Mach-O binary (32-bit)
    b"\xfe\xed\xfa\xcf",  # Mach-O binary (64-bit)
    b"\xce\xfa\xed\xfe",  # Mach-O reverse byte order
    b"\xcf\xfa\xed\xfe",  # Mach-O reverse byte order
    b"PK\x03\x04",        # ZIP / JAR / Office macro containers (unless explicitly vetted)
]


class InputSanitizer:
    """Validates and sanitizes textual inputs for incident reports and alerts."""

    @staticmethod
    def sanitize_string(text: Optional[str], field_name: str = "field", max_length: int = MAX_TEXT_INPUT_LENGTH) -> str:
        if text is None:
            return ""
        if not isinstance(text, str):
            text = str(text)

        if len(text) > max_length:
            raise ValueError(f"Input '{field_name}' exceeds maximum permitted length of {max_length} characters")

        # Strip null bytes and non-printable control characters (retain tabs and newlines)
        cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
        return cleaned.strip()

    @classmethod
    def sanitize_alert_payload(cls, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Validates structured alert dictionary against expected schema and bounds."""
        if not isinstance(payload, dict):
            raise ValueError("Alert payload must be a JSON dictionary object")

        if not payload:
            raise ValueError("Alert payload cannot be empty")

        required = ["incident_id", "alert_type", "description"]
        for req in required:
            val = payload.get(req)
            if not val or not str(val).strip():
                raise ValueError(f"Required field '{req}' is missing or blank")

        sanitized = {
            "incident_id": cls.sanitize_string(payload.get("incident_id"), "incident_id", max_length=128),
            "alert_type": cls.sanitize_string(payload.get("alert_type"), "alert_type", max_length=256),
            "description": cls.sanitize_string(payload.get("description"), "description", max_length=MAX_TEXT_INPUT_LENGTH),
            "severity": cls.sanitize_string(payload.get("severity", "Medium"), "severity", max_length=32),
            "affected_host": cls.sanitize_string(payload.get("affected_host", "Unknown"), "affected_host", max_length=256),
            "user_account": cls.sanitize_string(payload.get("user_account", "Unknown"), "user_account", max_length=256),
            "timestamp": cls.sanitize_string(payload.get("timestamp", ""), "timestamp", max_length=64),
            "raw_logs": cls.sanitize_string(payload.get("raw_logs", ""), "raw_logs", max_length=MAX_TEXT_INPUT_LENGTH),
        }

        # Normalize severity
        sev = sanitized["severity"].capitalize()
        if sev not in {"Critical", "High", "Medium", "Low"}:
            sanitized["severity"] = "Medium"
        else:
            sanitized["severity"] = sev

        return sanitized


class FileUploadValidator:
    """Validates uploaded log or incident files for size, extension, and binary safety."""

    @staticmethod
    def validate_filename(filename: str) -> str:
        if not filename or not isinstance(filename, str):
            raise ValueError("Filename must be a non-empty string")

        # Prevent directory traversal
        clean_name = os.path.basename(filename)
        clean_name = re.sub(r"[^a-zA-Z0-9_\.\-]", "_", clean_name)

        ext = os.path.splitext(clean_name)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            raise ValueError(f"File extension '{ext}' not allowed. Allowed types: {', '.join(sorted(ALLOWED_EXTENSIONS))}")

        return clean_name

    @classmethod
    def validate_file_content(cls, content_bytes: bytes, filename: str) -> Tuple[bool, str]:
        if len(content_bytes) == 0:
            return False, "File is empty"

        if len(content_bytes) > MAX_FILE_SIZE_BYTES:
            return False, f"File exceeds maximum allowed size of {MAX_FILE_SIZE_BYTES / (1024 * 1024)} MB"

        # Check binary magic signatures
        for magic in DISALLOWED_MAGIC_SIGNATURES:
            if content_bytes.startswith(magic):
                return False, f"Dangerous executable or binary format detected (Magic byte check: {magic!r})"

        # Verify UTF-8 or ASCII decodeable text
        try:
            content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            try:
                content_bytes.decode("latin-1")
            except Exception:
                return False, "File content is not valid text"

        return True, "File is valid"
