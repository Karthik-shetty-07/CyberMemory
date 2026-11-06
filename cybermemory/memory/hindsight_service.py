"""
Hindsight Memory Service implementation.
Wraps the official Hindsight SDK client with Retain, Recall, and Reflect operations,
multi-tenant memory bank separation, error resilience, and graceful fallback.
"""

import os
import json
from typing import List, Dict, Any, Optional
from cybermemory.models import HistoricalMatch
from cybermemory.memory.memory_mock import HindsightMemoryMock, MockMemoryItem


class HindsightMemoryService:
    """Production service interface for Vectorize Hindsight persistent agent memory."""

    DEFAULT_BANK = "cybermemory_soc_demo"

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        default_bank_id: str = DEFAULT_BANK,
        force_mock: bool = False,
        mock_persistence_file: Optional[str] = None
    ):
        self.api_key = api_key or os.getenv("HINDSIGHT_API_KEY", "")
        self.base_url = base_url or os.getenv("HINDSIGHT_API_URL", "http://localhost:8888")
        self.default_bank_id = default_bank_id
        self.force_mock = force_mock

        self._client = None
        self._is_live_connected = False
        self._mock = HindsightMemoryMock(persistence_file=mock_persistence_file)

        self._initialize_client()

    def _initialize_client(self) -> None:
        """Attempts to initialize the official hindsight-client if available and configured."""
        if self.force_mock:
            self._is_live_connected = False
            return

        try:
            from hindsight_client import Hindsight  # type: ignore
            # Initialize with API key or base URL
            if self.api_key:
                self._client = Hindsight(api_key=self.api_key, base_url=self.base_url)
            else:
                self._client = Hindsight(base_url=self.base_url)
            self._is_live_connected = True
        except (ImportError, Exception):
            # Graceful fallback to mock service
            self._is_live_connected = False
            self._client = None

    @property
    def is_live(self) -> bool:
        return self._is_live_connected and self._client is not None

    def retain_incident(
        self,
        incident_data: Dict[str, Any],
        bank_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Retains an incident investigation record into Hindsight persistent memory.
        Stores description, indicators, investigation steps, root cause, remediation,
        outcome, analyst feedback, and lessons learned.
        """
        target_bank = bank_id or self.default_bank_id

        # Format comprehensive incident memory text
        inc_id = incident_data.get("incident_id", "UNKNOWN_INC")
        alert_type = incident_data.get("alert_type", "Unknown Alert")
        description = incident_data.get("description", "")
        root_cause = incident_data.get("root_cause", "")
        remediation = incident_data.get("remediation", "")
        outcome = incident_data.get("final_outcome", "")
        feedback = incident_data.get("analyst_feedback", {})
        lessons = incident_data.get("lessons_learned", "")
        steps = incident_data.get("investigation_steps", [])

        iocs = incident_data.get("indicators", {})
        ioc_summary = (
            f"IPs: {', '.join(iocs.get('ip_addresses', []))}; "
            f"Domains: {', '.join(iocs.get('domains', []))}; "
            f"Hashes: {', '.join(iocs.get('file_hashes', []))}; "
            f"Processes: {', '.join(iocs.get('process_names', []))}"
        )

        content = (
            f"Incident ID: {inc_id}\n"
            f"Alert Type: {alert_type}\n"
            f"Description: {description}\n"
            f"Indicators: {ioc_summary}\n"
            f"Investigation Steps: {' | '.join(steps)}\n"
            f"Root Cause: {root_cause}\n"
            f"Remediation Applied: {remediation}\n"
            f"Final Outcome: {outcome}\n"
            f"Analyst Rating: {feedback.get('rating', 'Unrated')}; Analyst Notes: {feedback.get('comments', '')}\n"
            f"Lessons Learned: {lessons}"
        )

        metadata = {
            "incident_id": inc_id,
            "alert_type": alert_type,
            "severity": incident_data.get("severity", "Medium"),
            "root_cause": root_cause,
            "remediation": remediation,
            "outcome": outcome,
            "lessons_learned": lessons,
            "indicators": iocs,
            "steps": steps
        }

        if self.is_live:
            try:
                res = self._client.retain(bank_id=target_bank, content=content)
                return {"status": "success", "mode": "live_hindsight", "result": str(res)}
            except Exception as e:
                # Log and fallback to mock retention
                return self._mock.retain(bank_id=target_bank, content=content, metadata=metadata)
        else:
            res = self._mock.retain(bank_id=target_bank, content=content, metadata=metadata)
            res["mode"] = "local_hindsight_mock"
            return res

    def recall_similar_incidents(
        self,
        query: str,
        bank_id: Optional[str] = None,
        top_k: int = 3
    ) -> List[HistoricalMatch]:
        """
        Recalls semantically and indicator-relevant historical incidents from Hindsight.
        """
        target_bank = bank_id or self.default_bank_id

        if not query or not query.strip():
            return []

        raw_memories = []
        if self.is_live:
            try:
                live_results = self._client.recall(bank_id=target_bank, query=query)
                for mem in live_results[:top_k]:
                    # Extract score and content
                    score = getattr(mem, "score", 0.75)
                    content = getattr(mem, "content", str(mem))
                    raw_memories.append(MockMemoryItem(
                        memory_id="live_mem",
                        bank_id=target_bank,
                        content=content,
                        metadata={},
                        score=score
                    ))
            except Exception:
                # If live recall fails, run without pretending or fallback to mock
                raw_memories = self._mock.recall(bank_id=target_bank, query=query, top_k=top_k)
        else:
            raw_memories = self._mock.recall(bank_id=target_bank, query=query, top_k=top_k)

        matches = []
        for mem in raw_memories:
            meta = mem.metadata
            inc_id = meta.get("incident_id")
            if not inc_id:
                # Parse incident_id from text if metadata empty
                import re
                m = re.search(r"Incident ID:\s*(INC-\d{4}-\d{4})", mem.content)
                inc_id = m.group(1) if m else "HIST-REF"

            root_cause = meta.get("root_cause")
            if not root_cause:
                m = re.search(r"Root Cause:\s*([^\n]+)", mem.content)
                root_cause = m.group(1) if m else "Documented historical pattern"

            remediation = meta.get("remediation")
            if not remediation:
                m = re.search(r"Remediation Applied:\s*([^\n]+)", mem.content)
                remediation = m.group(1) if m else "Standard isolation applied"

            lessons = meta.get("lessons_learned")
            if not lessons:
                m = re.search(r"Lessons Learned:\s*([^\n]+)", mem.content)
                lessons = m.group(1) if m else "Verify IOCs across host network logs."

            steps = meta.get("steps")
            if not steps:
                steps = ["Refer to historical investigation procedure in memory."]

            matches.append(HistoricalMatch(
                incident_id=inc_id,
                similarity_score=round(mem.score, 3),
                relevance_explanation=f"Matched historical alert characteristics with similarity score {round(mem.score, 3)}.",
                historical_root_cause=root_cause,
                investigation_steps=steps,
                remediation_outcome=remediation,
                lessons_learned=lessons
            ))

        return matches

    def reflect_on_incidents(
        self,
        query: str,
        bank_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Synthesizes historical lessons and pattern abstractions across multiple incidents.
        """
        target_bank = bank_id or self.default_bank_id

        if self.is_live:
            try:
                resp = self._client.reflect(bank_id=target_bank, query=query)
                answer = getattr(resp, "answer", str(resp))
                return {"mode": "live_hindsight", "synthesis": answer}
            except Exception:
                resp = self._mock.reflect(bank_id=target_bank, query=query)
                return {"mode": "local_hindsight_mock", "synthesis": resp.answer}
        else:
            resp = self._mock.reflect(bank_id=target_bank, query=query)
            return {"mode": "local_hindsight_mock", "synthesis": resp.answer}

    def count_memories(self, bank_id: Optional[str] = None) -> int:
        target_bank = bank_id or self.default_bank_id
        return self._mock.get_bank_count(target_bank)

    def clear_bank(self, bank_id: Optional[str] = None) -> None:
        target_bank = bank_id or self.default_bank_id
        self._mock.clear(target_bank)

