import os
from dotenv import load_dotenv
from hindsight_client import Hindsight

load_dotenv()
BANK = "cybermemory-smoke"
client = Hindsight(
    base_url=os.environ["HINDSIGHT_URL"],
    api_key=os.environ["HINDSIGHT_API_KEY"],
    timeout=60.0,
)

client.create_bank(
    bank_id=BANK,
    name="CyberMemory smoke test",
    mission="SOC investigation memory: remember incidents, root causes, remediation and outcomes.",
)

client.retain(
    bank_id=BANK,
    content=(
        "Incident INC-001: Suspicious PowerShell with encoded command on host WS-014. "
        "Root cause: phishing macro. Remediation: isolated host, reset user credentials. "
        "Outcome: confirmed malicious."
    ),
    context="incident report",
    document_id="INC-001",
    metadata={"severity": "high", "type": "powershell"},
    retain_async=False,
)

res = client.recall(bank_id=BANK, query="encoded PowerShell on a workstation", budget="mid")
for r in res.results:
    print("RECALL:", r.type, "|", r.text)

ans = client.reflect(bank_id=BANK, query="What do we know about PowerShell incidents?", budget="low")
print("REFLECT:", ans.text)