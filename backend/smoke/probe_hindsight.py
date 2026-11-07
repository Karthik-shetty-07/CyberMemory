import os
from dotenv import load_dotenv
from hindsight_client import Hindsight

load_dotenv()
with Hindsight(
    base_url=os.environ["HINDSIGHT_URL"],
    api_key=os.environ["HINDSIGHT_API_KEY"],
    timeout=60.0,
) as client:
    try:
        client.create_bank(bank_id="cybermemory-smoke", name="again")
        print("create_bank on existing bank: OK, no error")
    except Exception as e:
        print("create_bank on existing bank:", type(e).__name__, str(e)[:200])

    res = client.recall(bank_id="cybermemory-smoke", query="encoded PowerShell", budget="low")
    r = res.results[0]
    print("TYPE:", type(r))
    print("FIELDS:", r.model_dump() if hasattr(r, "model_dump") else vars(r))
