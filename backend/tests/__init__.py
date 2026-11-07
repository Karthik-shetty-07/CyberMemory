"""Test package. Force local memory mode so tests never touch a live Hindsight bank."""
import os

for _name in ("HINDSIGHT_URL", "HINDSIGHT_API_URL", "HINDSIGHT_BASE_URL", "HINDSIGHT_API_KEY",
              "BACKEND_API_URL", "GROQ_API_KEY"):
    os.environ[_name] = ""
