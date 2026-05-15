# Negative fixture for PY-SECRETS-001. NONE of these should fire.

import os
from openai import OpenAI


def make_client():
    # read from the environment, not a literal
    return OpenAI(api_key=os.environ["OPENAI_API_KEY"])


def make_client_getenv():
    return OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


# placeholder substrings are gated out
PLACEHOLDER = "your_key_here_replace_before_prod"
ALSO_PLACEHOLDER = "sk-...xxxxxxxxxxxxxxxxxxxxxxxx..."
