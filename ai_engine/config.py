"""
config.py — Configuration loader for the AI & Incident Intelligence module.

Loads environment variables from the .env file and validates that required
keys are present. The actual API key value is NEVER printed or logged.
"""

import os
from dotenv import load_dotenv

# Load variables from .env into the environment
load_dotenv()


def get_groq_api_key() -> str:
    """
    Reads the GROQ_API_KEY from environment variables.

    Returns:
        str: The API key string.

    Raises:
        EnvironmentError: If the key is missing or empty.
    """
    api_key = os.getenv("GROQ_API_KEY")

    if not api_key or api_key.strip() == "":
        raise EnvironmentError(
            "[ERROR] GROQ_API_KEY is not set. "
            "Please add your key to the .env file:\n"
            "  GROQ_API_KEY=your_actual_key_here"
        )

    return api_key
