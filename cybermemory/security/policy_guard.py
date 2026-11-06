"""
Operational policy guard and read-only analysis enforcement.
Ensures zero execution of extracted commands, prevents unauthorized autonomous remediation,
and strictly enforces separation of confirmed evidence from AI hypotheses.
"""

from enum import Enum
from typing import List, Dict, Any, Tuple


class OperationalMode(str, Enum):
    READ_ONLY_ANALYSIS = "READ_ONLY_ANALYSIS"
    INTERACTIVE_SANDBOX = "INTERACTIVE_SANDBOX"


# Potentially destructive / operational command keywords
BLOCKED_EXECUTION_COMMANDS = [
    "rm", "del", "vssadmin", "bcdedit", "powershell", "cmd.exe", "bash", "sh",
    "kill", "taskkill", "iptables", "netsh", "format", "curl", "wget", "nc",
    "ncat", "socat", "drop", "truncate", "shutdown", "reboot", "isolate"
]


class PolicyGuard:
    """Enforces cybersecurity safety guardrails and read-only constraints."""

    def __init__(self, mode: OperationalMode = OperationalMode.READ_ONLY_ANALYSIS):
        self.mode = mode

    def assert_read_only(self) -> None:
        """Verifies that the system is operating strictly in read-only analysis mode."""
        if self.mode != OperationalMode.READ_ONLY_ANALYSIS:
            raise PermissionError(f"System operation restricted: Only READ_ONLY_ANALYSIS is permitted, got {self.mode}")

    def block_command_execution(self, command_str: str) -> None:
        """Strictly blocks any system or shell execution attempt."""
        # Always block command execution from report data
        raise PermissionError(
            f"SECURITY POLICY VIOLATION: Execution of system commands is strictly prohibited in CyberMemory AI. "
            f"Blocked command: '{command_str[:100]}...'"
        )

    def audit_containment_action(self, action_description: str) -> Dict[str, Any]:
        """
        Validates that a containment recommendation is strictly advisory
        and requires explicit analyst human-in-the-loop signoff.
        """
        self.assert_read_only()

        # Check for automated triggers
        is_automated = any(phrase in action_description.lower() for phrase in [
            "automatically execute", "auto-isolate", "self-executing", "run immediately without prompt"
        ])

        if is_automated:
            return {
                "allowed": False,
                "reason": "Automated containment execution is prohibited. All actions require manual analyst approval.",
                "tagged_action": f"[BLOCKED_AUTOMATION] {action_description}"
            }

        return {
            "allowed": True,
            "requires_human_approval": True,
            "status": "ADVISORY_ONLY",
            "tagged_action": f"[RECOMMENDATION ONLY - REQUIRES HUMAN AUTHORIZATION] {action_description}"
        }

    @staticmethod
    def tag_evidence_distinction(
        observed_facts: List[str],
        historical_context: List[str],
        ai_hypotheses: List[str]
    ) -> Dict[str, List[str]]:
        """
        Guarantees that raw observed facts, historical memory precedents,
        and speculative AI hypotheses are unmistakably distinguished.
        """
        return {
            "confirmed_observations": [f"[CONFIRMED OBSERVATION] {f}" for f in observed_facts],
            "historical_precedents": [f"[HISTORICAL MEMORY] {h}" for h in historical_context],
            "ai_hypotheses": [f"[AI HYPOTHESIS - UNCONFIRMED] {hyp}" for hyp in ai_hypotheses]
        }
