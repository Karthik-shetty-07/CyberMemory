"""Validate report structure and evidence references."""

from typing import List, Mapping


def validate_report(report: Mapping[str, object]) -> List[str]:
    """Return validation errors, or an empty list when the report is valid."""
    raise NotImplementedError