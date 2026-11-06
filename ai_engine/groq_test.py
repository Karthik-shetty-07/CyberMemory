"""
groq_test.py — Basic Groq API connection test for CyberMemory.

Sends a simple cybersecurity-related question to the Groq API and
prints the AI response. Run this script to verify your API key works.

Usage:
    python ai_engine/groq_test.py
"""

from groq import Groq, APIConnectionError, AuthenticationError, RateLimitError
from config import get_groq_api_key


def test_groq_connection():
    """
    Creates a Groq client and sends a test cybersecurity question.
    Handles common API errors and prints a clear message for each case.
    """

    # --- Load API key ---
    try:
        api_key = get_groq_api_key()
    except EnvironmentError as e:
        print(e)
        return

    # --- Initialise Groq client ---
    client = Groq(api_key=api_key)

    # --- Build the prompt ---
    messages = [
        {
            "role": "system",
            "content": (
                "You are a cybersecurity expert assistant. "
                "Provide clear, concise explanations."
            ),
        },
        {
            "role": "user",
            "content": "What are the top three signs that a network may be under a DDoS attack?",
        },
    ]

    # --- Send request and print response ---
    try:
        print("[INFO] Connecting to Groq API …")

        response = client.chat.completions.create(
            model="openai/gpt-oss-120b",
            messages=messages,
            temperature=0.7,
            max_tokens=512,
        )

        ai_reply = response.choices[0].message.content
        print("\n[SUCCESS] Groq API responded:\n")
        print(ai_reply)

    except AuthenticationError:
        print("[ERROR] Authentication failed. Check that your GROQ_API_KEY is correct.")
    except RateLimitError:
        print("[ERROR] Rate limit exceeded. Wait a moment and try again.")
    except APIConnectionError as e:
        print(f"[ERROR] Could not connect to Groq API: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")


if __name__ == "__main__":
    test_groq_connection()
