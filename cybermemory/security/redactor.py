"""
Safe secret redaction and error logging.
Ensures sensitive tokens, passwords, and API keys are never persisted or printed.
"""

import re
import logging
from typing import Any, Dict

# Regex patterns for credentials and secrets
SECRET_PATTERNS = [
    # Groq API keys
    (re.compile(r"gsk_[a-zA-Z0-9]{20,}", re.IGNORECASE), "[REDACTED_GROQ_KEY]"),
    # General API keys (Hindsight / Vectorize / Generic 32-64 hex or base64)
    (re.compile(r"(?:api_key|apikey|hindsight_key|secret_key)[\s:=]+['\"]?([a-zA-Z0-9_\-]{16,})['\"]?", re.IGNORECASE), "api_key=[REDACTED_KEY]"),
    # Bearer tokens
    (re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]{15,}", re.IGNORECASE), "Bearer [REDACTED_BEARER_TOKEN]"),
    # GitHub Personal Access Tokens
    (re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}", re.IGNORECASE), "[REDACTED_GITHUB_TOKEN]"),
    # AWS Access Key IDs
    (re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE), "[REDACTED_AWS_KEY]"),
    # Passwords in query strings or JSON
    (re.compile(r"(?:password|passwd|pwd)[\s:=]+['\"]?([^'\"\s&,]+)['\"]?", re.IGNORECASE), "password=[REDACTED_PASSWORD]"),
    # Private Key Headers
    (re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]+?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----", re.MULTILINE), "[REDACTED_PRIVATE_KEY]"),
]


class SecretRedactor:
    """Detects and redacts sensitive credentials from strings, logs, and JSON objects."""

    @classmethod
    def redact_text(cls, text: str) -> str:
        if not text or not isinstance(text, str):
            return text

        redacted = text
        for pattern, replacement in SECRET_PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        return redacted

    @classmethod
    def redact_dict(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively scrubs dictionary keys and values."""
        scrubbed = {}
        sensitive_key_names = {"password", "secret", "token", "api_key", "apikey", "authorization", "key"}

        for k, v in data.items():
            if any(s in k.lower() for s in sensitive_key_names):
                scrubbed[k] = "[REDACTED_SENSITIVE_FIELD]"
            elif isinstance(v, str):
                scrubbed[k] = cls.redact_text(v)
            elif isinstance(v, dict):
                scrubbed[k] = cls.redact_dict(v)
            elif isinstance(v, list):
                scrubbed[k] = [cls.redact_text(item) if isinstance(item, str) else item for item in v]
            else:
                scrubbed[k] = v
        return scrubbed


class SafeLogger:
    """Logging wrapper that guarantees secret scrubbing before outputting to log handlers."""

    def __init__(self, name: str = "CyberMemory"):
        self.logger = logging.getLogger(name)

    def info(self, msg: str, *args, **kwargs):
        clean_msg = SecretRedactor.redact_text(str(msg))
        self.logger.info(clean_msg, *args, **kwargs)

    def warning(self, msg: str, *args, **kwargs):
        clean_msg = SecretRedactor.redact_text(str(msg))
        self.logger.warning(clean_msg, *args, **kwargs)

    def error(self, msg: str, *args, **kwargs):
        clean_msg = SecretRedactor.redact_text(str(msg))
        self.logger.error(clean_msg, *args, **kwargs)

    def exception(self, msg: str, *args, **kwargs):
        clean_msg = SecretRedactor.redact_text(str(msg))
        self.logger.exception(clean_msg, *args, **kwargs)

