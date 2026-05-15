# Positive fixture for PY-TLS-VERIFY-001 (XL-004 TLS Verification Disabled).
# Each line below MUST be flagged.

import requests
import httpx
import urllib3


def fetch(url):
    return requests.get(url, verify=False)


def post(url, data):
    return requests.post(url, json=data, verify=False)


def client():
    return httpx.Client(verify=False)


def silence():
    urllib3.disable_warnings()
