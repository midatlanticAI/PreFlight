# Negative fixture for PY-TLS-VERIFY-001. NONE of these should fire.

import requests
import httpx


def fetch(url):
    # default verification on
    return requests.get(url)


def fetch_with_ca(url):
    # a CA bundle path is the fix, not the bug
    return requests.get(url, verify="/etc/ssl/certs/ca-bundle.pem")


def client():
    # default client verifies
    return httpx.Client()
