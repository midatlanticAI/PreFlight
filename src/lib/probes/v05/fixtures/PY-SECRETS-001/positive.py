# Positive fixture for PY-SECRETS-001 (XL-006 Hardcoded Secrets).
# Synthetic, low-entropy values: they match the adapter regex but cannot
# trip GitHub push protection (no real provider key here). Each line fires.

from openai import OpenAI


def make_client():
    # api_key= literal with no env reference and no placeholder substring
    return OpenAI(api_key="abcdefghijklmnopqrstuvwxyz0123456789")


# Google/Gemini key shape: AIza + 35 chars. Low-entropy synthetic value.
GOOGLE_KEY = "AIzaSyA0000000000000000000000000000000"

# Groq key shape: gsk_ + 30+ chars. Synthetic.
GROQ_KEY = "gsk_000000000000000000000000000000000000000000"
