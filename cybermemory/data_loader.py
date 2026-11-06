"""
Dataset loader and validator for CyberMemory synthetic incident records.
"""

import json
import os
from typing import List, Dict, Any, Optional


REQUIRED_INCIDENT_FIELDS = [
    "incident_id",
    "timestamp",
    "alert_type",
    "severity",
    "description",
    "affected_host",
    "indicators",
    "investigation_steps",
    "root_cause",
    "remediation",
    "final_outcome",
    "analyst_feedback"
]

REQUIRED_INDICATOR_FIELDS = [
    "ip_addresses",
    "domains",
    "urls",
    "file_hashes",
    "process_names",
    "file_paths",
    "registry_keys"
]


class IncidentDataLoader:
    """Manages loading, validation, and querying of synthetic incident datasets."""

    def __init__(self, dataset_path: Optional[str] = None):
        if dataset_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            dataset_path = os.path.join(base_dir, "data", "synthetic_incidents.json")
        self.dataset_path = dataset_path
        self._incidents: List[Dict[str, Any]] = []
        self._load_and_validate()

    def _load_and_validate(self) -> None:
        if not os.path.exists(self.dataset_path):
            raise FileNotFoundError(f"Incident dataset not found at {self.dataset_path}")

        with open(self.dataset_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, list):
            raise ValueError("Dataset root must be a JSON array of incident objects")

        validated = []
        for idx, inc in enumerate(data):
            self._validate_incident_record(inc, idx)
            validated.append(inc)

        self._incidents = validated

    @staticmethod
    def _validate_incident_record(inc: Dict[str, Any], index: int) -> None:
        for field in REQUIRED_INCIDENT_FIELDS:
            if field not in inc:
                raise ValueError(f"Record at index {index} missing required field: '{field}'")

        indicators = inc.get("indicators", {})
        if not isinstance(indicators, dict):
            raise ValueError(f"Record {inc.get('incident_id')} 'indicators' must be a dict")

        for ind_field in REQUIRED_INDICATOR_FIELDS:
            if ind_field not in indicators:
                raise ValueError(f"Record {inc.get('incident_id')} indicators missing '{ind_field}'")
            if not isinstance(indicators[ind_field], list):
                raise ValueError(f"Record {inc.get('incident_id')} indicators['{ind_field}'] must be a list")

        feedback = inc.get("analyst_feedback", {})
        if not isinstance(feedback, dict) or "rating" not in feedback or "comments" not in feedback:
            raise ValueError(f"Record {inc.get('incident_id')} must have analyst_feedback with rating and comments")

    def get_all(self) -> List[Dict[str, Any]]:
        return list(self._incidents)

    def get_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        for inc in self._incidents:
            if inc.get("incident_id") == incident_id:
                return inc
        return None

    def filter_by_type(self, alert_type: str) -> List[Dict[str, Any]]:
        return [inc for inc in self._incidents if alert_type.lower() in inc.get("alert_type", "").lower()]

    def filter_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        return [inc for inc in self._incidents if inc.get("severity", "").lower() == severity.lower()]

    def search_text(self, query: str) -> List[Dict[str, Any]]:
        q = query.lower()
        results = []
        for inc in self._incidents:
            blob = (
                f"{inc.get('alert_type', '')} {inc.get('description', '')} "
                f"{inc.get('root_cause', '')} {inc.get('remediation', '')} "
                f"{json.dumps(inc.get('indicators', {}))}"
            ).lower()
            if q in blob:
                results.append(inc)
        return results

    def get_statistics(self) -> Dict[str, Any]:
        categories: Dict[str, int] = {}
        severities: Dict[str, int] = {}
        total_iocs = 0

        for inc in self._incidents:
            atype = inc.get("alert_type", "Unknown")
            categories[atype] = categories.get(atype, 0) + 1

            sev = inc.get("severity", "Unknown")
            severities[sev] = severities.get(sev, 0) + 1

            for _, vals in inc.get("indicators", {}).items():
                if isinstance(vals, list):
                    total_iocs += len(vals)

        return {
            "total_incidents": len(self._incidents),
            "categories_count": len(categories),
            "categories": categories,
            "severities": severities,
            "total_extracted_iocs": total_iocs
        }
