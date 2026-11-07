import os
from dotenv import load_dotenv

load_dotenv()

# Accept any of the names used across this repo's docs and .env.example.
HINDSIGHT_URL = (
    os.environ.get("HINDSIGHT_URL")
    or os.environ.get("HINDSIGHT_API_URL")
    or os.environ.get("HINDSIGHT_BASE_URL")
    or ""
).rstrip("/")
HINDSIGHT_API_KEY = os.environ.get("HINDSIGHT_API_KEY", "")
BANK_PREFIX = os.environ.get("BANK_PREFIX", "cybermemory")
HINDSIGHT_TIMEOUT = float(os.environ.get("HINDSIGHT_TIMEOUT", "30"))