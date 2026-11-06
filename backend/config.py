import os
from dotenv import load_dotenv

load_dotenv()

HINDSIGHT_URL = os.environ.get("HINDSIGHT_URL", "")
HINDSIGHT_API_KEY = os.environ.get("HINDSIGHT_API_KEY", "")
BANK_PREFIX = os.environ.get("BANK_PREFIX", "cybermemory")
HINDSIGHT_TIMEOUT = float(os.environ.get("HINDSIGHT_TIMEOUT", "30"))