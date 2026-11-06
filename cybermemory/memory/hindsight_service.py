"""
Hindsight Memory Service implementation.
Wraps the official Hindsight SDK client with Retain, Recall, and Reflect operations,
multi-tenant memory bank separation, error resilience, and graceful fallback.
"""

import os
import re
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
            if self.api_key:
                client = Hindsight(api_key=self.api_key, base_url=self.base_url)
            else:
                client = Hindsight(base_url=self.base_url)
            # Real connectivity check: only report live after the server answers.
            client.get_version()
            self._client = client
            self._is_live_connected = True
        except Exception:
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
                live_meta = {k: (v if isinstance(v, str) else json.dumps(v)) for k, v in metadata.items()}
                res = self._client.retain(
                    bank_id=target_bank, content=content, context="security incident report",
                    document_id=inc_id, metadata=live_meta,
                )
                # Keep the structured copy locally too, so recall can rebuild full matches.
                self._mock.retain(bank_id=target_bank, content=content, metadata=metadata)
                return {"status": "success", "mode": "live_hindsight", "result": str(res)}
            except Exception:
                res = self._mock.retain(bank_id=target_bank, content=content, metadata=metadata)
                res["mode"] = "local_hindsight_mock_fallback"
                return res
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
                response = self._client.recall(bank_id=target_bank, query=query)
                results = list(getattr(response, "results", None) or [])[:top_k]
                n = len(results)
                for rank, mem in enumerate(results):
                    text = getattr(mem, "text", "") or ""
                    # The SDK returns results ranked, without a score; derive one from rank.
                    score = getattr(mem, "score", None)
                    if score is None:
                        score = round(1.0 - rank / max(n, 1) * 0.5, 3)
                    m = re.search(r"Incident ID:\s*(INC-\d{4}-\d{4})", text)
                    local = self._mock.find_by_incident(target_bank, m.group(1)) if m and hasattr(self._mock, "find_by_incident") else None
                    raw_memories.append(MockMemoryItem(
                        memory_id=getattr(mem, "id", "live_mem") or "live_mem",
                        bank_id=target_bank,
                        content=text,
                        metadata=local.metadata if local else {},
                        score=score,
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
                answer = getattr(resp, "text", None) or str(resp)
                return {"mode": "live_hindsight", "synthesis": answer}
            except Exception:
                resp = self._mock.reflect(bank_id=target_bank, query=query)
                return {"mode": "local_hindsight_mock", "synthesis": resp.answer}
        else:
            resp = self._mock.reflect(bank_id=target_bank, query=query)
            return {"mode": "local_hindsight_mock", "synthesis": resp.answer}

    def count_memories(self, bank_id: Optional[str] = None) -> int:
        target_bank = bank_id or self.default_bank_id
        if self.is_live:
            try:
                res = self._client.list_memories(bank_id=target_bank, limit=1, offset=0)
                return int(getattr(res, "total", 0) or 0)
            except Exception:
                pass
        return self._mock.get_bank_count(target_bank)

    def clear_bank(self, bank_id: Optional[str] = None) -> None:
        target_bank = bank_id or self.default_bank_id
        if self.is_live:
            try:
                self._client.delete_bank(bank_id=target_bank)
            except Exception:
                pass
        self._mock.clear(target_bank)

