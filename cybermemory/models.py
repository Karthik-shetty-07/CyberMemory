"""
Data models and schemas for CyberMemory AI.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone


@dataclass
class ExtractedIndicators:
    ip_addresses: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    file_hashes: List[str] = field(default_factory=list)
    process_names: List[str] = field(default_factory=list)
    file_paths: List[str] = field(default_factory=list)
    registry_keys: List[str] = field(default_factory=list)
    user_accounts: List[str] = field(default_factory=list)
    hostnames: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AlertInput:
    incident_id: str
    alert_type: str
    description: str
    severity: str = "Medium"
    affected_host: str = "Unknown"
    user_account: str = "Unknown"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    raw_logs: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HistoricalMatch:
    incident_id: str
    similarity_score: float
    relevance_explanation: str
    historical_root_cause: str
    investigation_steps: List[str]
    remediation_outcome: str
    lessons_learned: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationStep:
    priority: int  # 1 (Highest) to 5
    action: str
    reason: str
    evidence_to_collect: str
    expected_result: str
    historical_reference: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationReport:
    incident_id: str
    timestamp: str
    incident_summary: str
    severity_assessment: str  # Critical, High, Medium, Low
    severity_rationale: str
    extracted_indicators: ExtractedIndicators
    historical_correlation: List[HistoricalMatch]
    memory_status: str  # "Active Memory (N matches)", "Cold Start (Empty Memory)", "Degraded Mode"
    investigation_plan: List[InvestigationStep]
    potential_root_causes: List[str]
    recommended_containment: List[str]
    confidence_and_limitations: str
    operational_mode: str = "READ_ONLY_ANALYSIS"
    contains_hypotheses: bool = True

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        return data


@dataclass
class AnalystFeedback:
    incident_id: str
    rating: str  # "Helpful", "Partially Helpful", "Not Helpful"
    comments: str
    actual_outcome: str
    analyst_name: str = "analyst_1"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

