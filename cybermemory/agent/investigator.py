"""
Incident Investigator Engine.
Coordinates IOC extraction, Hindsight memory recall, LLM synthesis,
and security guardrails into a structured investigation report.
"""

import os
import json
from typing import Dict, Any, List, Optional
from cybermemory.models import (
    AlertInput,
    InvestigationReport,
    HistoricalMatch,
    InvestigationStep,
    ExtractedIndicators,
)
from cybermemory.security.sanitizer import InputSanitizer
from cybermemory.security.prompt_injection import PromptInjectionGuard
from cybermemory.security.policy_guard import PolicyGuard, OperationalMode
from cybermemory.security.redactor import SecretRedactor, SafeLogger
from cybermemory.memory.hindsight_service import HindsightMemoryService
from cybermemory.agent.indicator_extractor import IndicatorExtractor
from cybermemory.agent.prompt_templates import (
    INVESTIGATION_SYSTEM_PROMPT,
    build_investigation_prompt,
)


class IncidentInvestigator:
    """Core investigation orchestrator for CyberMemory AI."""

    def __init__(
        self,
        memory_service: Optional[HindsightMemoryService] = None,
        groq_api_key: Optional[str] = None,
        groq_model: str = "openai/gpt-oss-120b",
        force_mock_llm: bool = False
    ):
        self.logger = SafeLogger("IncidentInvestigator")
        self.memory_service = memory_service or HindsightMemoryService()
        self.groq_api_key = groq_api_key or os.getenv("GROQ_API_KEY", "")
        self.groq_model = groq_model
        self.force_mock_llm = force_mock_llm
        self.policy_guard = PolicyGuard(OperationalMode.READ_ONLY_ANALYSIS)
        self.prompt_guard = PromptInjectionGuard()

    def investigate(self, alert_raw: Dict[str, Any], bank_id: Optional[str] = None) -> InvestigationReport:
        """
        Executes end-to-end incident investigation workflow:
        1. Sanitize input & detect prompt injections.
        2. Extract IOCs.
        3. Recall relevant historical memories from Hindsight.
        4. Synthesize investigation findings via LLM or deterministic engine.
        5. Enforce read-only analysis and distinction guardrails.
        """
        # Step 1: Input Sanitization
        sanitized_alert = InputSanitizer.sanitize_alert_payload(alert_raw)
        inc_id = sanitized_alert["incident_id"]
        alert_type = sanitized_alert["alert_type"]

        # Step 2: Prompt Injection Check
        is_injection, detected_patterns = self.prompt_guard.scan_alert(sanitized_alert)
        if is_injection:
            self.logger.warning(f"Adversarial prompt injection pattern detected in alert {inc_id}: {detected_patterns}")

        # Step 3: Extract Indicators
        combined_text = f"{sanitized_alert['description']} {sanitized_alert.get('raw_logs', '')} {sanitized_alert.get('affected_host', '')}"
        extracted_iocs = IndicatorExtractor.extract_from_text(combined_text)

        # Step 4: Recall from Hindsight Memory
        # Build query focused on alert type, indicators, and behavior
        query_parts = [alert_type, sanitized_alert["description"]]
        if extracted_iocs.domains:
            query_parts.extend(extracted_iocs.domains)
        if extracted_iocs.process_names:
            query_parts.extend(extracted_iocs.process_names)
        recall_query = " ".join(query_parts)

        historical_matches: List[HistoricalMatch] = []
        try:
            historical_matches = self.memory_service.recall_similar_incidents(
                query=recall_query,
                bank_id=bank_id,
                top_k=3
            )
        except Exception as e:
            self.logger.error(f"Hindsight recall failed: {e}")
            historical_matches = []

        if historical_matches:
            memory_status = f"Active Memory ({len(historical_matches)} historical cases retrieved)"
        else:
            memory_status = "Cold Start (Empty Memory) - Running without historical context"

        # Step 5: LLM Reasoning Synthesis
        report_data = self._generate_analysis(
            sanitized_alert=sanitized_alert,
            extracted_iocs=extracted_iocs,
            historical_matches=historical_matches,
            memory_status=memory_status,
            is_injection_flagged=is_injection
        )

        # Step 6: Security Policy Guard Enforcement
        # Ensure all recommended containment steps are strictly advisory
        audited_containment = []
        for c in report_data.get("recommended_containment", []):
            audit = self.policy_guard.audit_containment_action(c)
            audited_containment.append(audit["tagged_action"])

        # Construct final report
        plan_steps = [
            InvestigationStep(
                priority=s.get("priority", 1),
                action=s.get("action", ""),
                reason=s.get("reason", ""),
                evidence_to_collect=s.get("evidence_to_collect", ""),
                expected_result=s.get("expected_result", ""),
                historical_reference=s.get("historical_reference")
            )
            for s in report_data.get("investigation_plan", [])
        ]

        report = InvestigationReport(
            incident_id=inc_id,
            timestamp=sanitized_alert.get("timestamp", ""),
            incident_summary=report_data.get("incident_summary", ""),
            severity_assessment=report_data.get("severity_assessment", sanitized_alert["severity"]),
            severity_rationale=report_data.get("severity_rationale", ""),
            extracted_indicators=extracted_iocs,
            historical_correlation=historical_matches,
            memory_status=memory_status,
            investigation_plan=plan_steps,
            potential_root_causes=report_data.get("potential_root_causes", []),
            recommended_containment=audited_containment,
            confidence_and_limitations=report_data.get("confidence_and_limitations", ""),
            operational_mode="READ_ONLY_ANALYSIS",
            contains_hypotheses=True
        )

        return report

    def _generate_analysis(
        self,
        sanitized_alert: Dict[str, Any],
        extracted_iocs: ExtractedIndicators,
        historical_matches: List[HistoricalMatch],
        memory_status: str,
        is_injection_flagged: bool
    ) -> Dict[str, Any]:
        """Invokes Groq API or performs structured synthesis if API is unavailable."""
        if not self.force_mock_llm and self.groq_api_key:
            try:
                return self._call_groq_llm(sanitized_alert, extracted_iocs, historical_matches)
            except Exception as e:
                self.logger.error(f"Groq API inference failed, falling back to deterministic reasoning: {e}")

        # Deterministic Expert Rule Engine
        return self._deterministic_synthesize(sanitized_alert, extracted_iocs, historical_matches, is_injection_flagged)

    def _call_groq_llm(
        self,
        sanitized_alert: Dict[str, Any],
        extracted_iocs: ExtractedIndicators,
        historical_matches: List[HistoricalMatch]
    ) -> Dict[str, Any]:
        """Calls Groq API using OpenAI-compatible client interface."""
        from openai import OpenAI  # type: ignore
        client = OpenAI(
            base_url="https://api.groq.com/openai/v1",
            api_key=self.groq_api_key
        )

        prompt = build_investigation_prompt(
            alert_dict=sanitized_alert,
            historical_matches=historical_matches,
            extracted_iocs=extracted_iocs.to_dict()
        )

        response = client.chat.completions.create(
            model=self.groq_model,
            messages=[
                {"role": "system", "content": INVESTIGATION_SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            response_format={"type": "json_object"}
        )

        content = response.choices[0].message.content
        return json.loads(content)

    def _deterministic_synthesize(
        self,
        sanitized_alert: Dict[str, Any],
        extracted_iocs: ExtractedIndicators,
        historical_matches: List[HistoricalMatch],
        is_injection_flagged: bool
    ) -> Dict[str, Any]:
        """
        High-fidelity cybersecurity reasoning synthesizer.
        Accurately differentiates cold-start recommendations from memory-informed recommendations.
        """
        alert_type = sanitized_alert["alert_type"]
        desc = sanitized_alert["description"]
        host = sanitized_alert["affected_host"]
        user = sanitized_alert["user_account"]

        # Prompt injection defanging note
        injection_warning = ""
        if is_injection_flagged:
            injection_warning = " [SECURITY NOTICE: Potential prompt injection directives in alert text were quarantined and disregarded.]"

        # Cold Start vs Warm Memory differentiation
        if not historical_matches:
            # Baseline generic playbook
            summary = (
                f"[CONFIRMED OBSERVATION] Detected suspicious activity matching pattern '{alert_type}' "
                f"on host {host} affecting user account {user}.{injection_warning} "
                f"No prior incident memory was available in Hindsight (Cold Start mode)."
            )
            rationale = (
                f"Initial severity classified as {sanitized_alert['severity']} based on baseline SOC playbook criteria. "
                f"Historical variance is unknown due to empty memory."
            )
            plan = [
                {
                    "priority": 1,
                    "action": "Query host endpoint logs for process lineage and parent process ID",
                    "reason": "Identify the initial process execution vector",
                    "evidence_to_collect": "Windows Security Event 4688 / Sysmon Event 1",
                    "expected_result": "Determine if execution originated from browser, email client, or script interpreter",
                    "historical_reference": None
                },
                {
                    "priority": 2,
                    "action": "Inspect perimeter firewall and proxy logs for connections to extracted domains/IPs",
                    "reason": "Verify if external command and control (C2) communication occurred",
                    "evidence_to_collect": "Proxy egress flow logs and DNS query history",
                    "expected_result": "Confirm whether payload transfer or beaconing succeeded",
                    "historical_reference": None
                },
                {
                    "priority": 3,
                    "action": "Check user account authentication logs for anomalies",
                    "reason": "Assess whether account credentials were stolen or compromised",
                    "evidence_to_collect": "Domain Controller Event 4624 / 4625",
                    "expected_result": "Identify concurrent or abnormal logon sessions",
                    "historical_reference": None
                }
            ]
            root_causes = [
                f"[AI HYPOTHESIS] Standard execution vector for {alert_type} (e.g. spearphishing, unpatched vulnerability, or rogue script).",
                "[AI HYPOTHESIS] Potential testing or benign administrator automation requiring analyst verification."
            ]
            containment = [
                f"Isolate host {host} from the network via EDR console.",
                f"Temporarily suspend Active Directory credentials for account {user}.",
                "Block any extracted IP addresses and external domains at edge firewalls."
            ]
            limitations = (
                "Confidence is moderate (65%). In the absence of historical incident memory, "
                "this plan relies on general threat response heuristics. "
                "Investigator must manually correlate with other assets on subnet."
            )
        else:
            # Warm Memory Mode: Informed by prior investigations!
            top_match = historical_matches[0]
            summary = (
                f"[CONFIRMED OBSERVATION] Detected suspicious activity matching pattern '{alert_type}' "
                f"on host {host} affecting user account {user}.{injection_warning} "
                f"[HISTORICAL CONTEXT] Highly correlated with past incident {top_match.incident_id} "
                f"(relevance score {top_match.similarity_score}): {top_match.relevance_explanation}"
            )
            rationale = (
                f"Severity evaluated as {sanitized_alert['severity']}. Elevated confidence due to direct correlation "
                f"with past incident {top_match.incident_id} which was previously resolved as a confirmed threat."
            )

            # Build memory-informed investigation plan
            plan = [
                {
                    "priority": 1,
                    "action": f"Fast-track validation of parent process and memory bypass signatures identified in {top_match.incident_id}",
                    "reason": f"Historical precedent {top_match.incident_id} demonstrated root cause: '{top_match.historical_root_cause}'",
                    "evidence_to_collect": "EDR process tree memory dump and script-block telemetry (Event ID 4104)",
                    "expected_result": "Confirm whether the same weaponized dropper or payload variant was used",
                    "historical_reference": top_match.incident_id
                },
                {
                    "priority": 2,
                    "action": f"Cross-verify IOC indicators against firewall blocklists deployed during {top_match.incident_id}",
                    "reason": f"Verify if threat actor reused infrastructure identified in {top_match.incident_id}",
                    "evidence_to_collect": "Zeek / NetFlow egress logs and DNS sinkhole match counters",
                    "expected_result": "Determine whether egress was automatically blocked or active",
                    "historical_reference": top_match.incident_id
                },
                {
                    "priority": 3,
                    "action": f"Execute remediation verification steps established in {top_match.incident_id}",
                    "reason": f"Past incident lessons learned: '{top_match.lessons_learned}'",
                    "evidence_to_collect": "User Kerberos ticket cache and scheduled task audit logs",
                    "expected_result": "Confirm complete eradication of secondary persistence mechanisms",
                    "historical_reference": top_match.incident_id
                }
            ]

            root_causes = [
                f"[HISTORICAL CONTEXT] Direct correlation with {top_match.incident_id}: '{top_match.historical_root_cause}'.",
                f"[AI HYPOTHESIS] Secondary campaign or lateral propagation from identical adversary infrastructure targeting subnet {host}."
            ]

            containment = [
                f"Execute established runbook from {top_match.incident_id}: {top_match.remediation_outcome}",
                f"Isolate host {host} immediately and revoke session tokens for {user}.",
                f"Sweep all adjacent workstations in subnet {host.split('.')[0]} for related indicators."
            ]

            limitations = (
                f"Confidence is high (92%). Grounded by Hindsight memory retrieval of {top_match.incident_id}. "
                f"Analyst must confirm whether host {host} exhibits secondary persistence mechanisms before un-quarantine."
            )

        return {
            "incident_summary": summary,
            "severity_assessment": sanitized_alert["severity"],
            "severity_rationale": rationale,
            "investigation_plan": plan,
            "potential_root_causes": root_causes,
            "recommended_containment": containment,
            "confidence_and_limitations": limitations
        }
