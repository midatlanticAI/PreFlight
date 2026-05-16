---
title: Python project
slug: python-project
type: shape
last_updated: 2026-05-15
draft: false
related_probe_ids:
  - Architecture
related_incident_slugs: []
sources:
  - title: Django — deployment checklist
    url: https://docs.djangoproject.com/en/stable/howto/deployment/checklist/
  - title: CWE-502 — Deserialization of Untrusted Data
    url: https://cwe.mitre.org/data/definitions/502.html
summary: A Python codebase (Django, Flask, FastAPI, or scripts). The classifier switches probe targeting to Python source; the recurring vibe-coded failures are the framework default left on and the unsafe load left in.
---

## What this shape is

A project with `pyproject.toml`, `setup.py`, or `requirements.txt`. The
classifier reports it as a Python Project and routes the Python language
adapters at the source while skipping JS-specific probes.

## Scanner behavior

Pre-Flight classifies this shape (informational). It does not raise a
shape-specific finding for it, but the Python XL adapters
(deserialization, raw SQL, TLS verification, secrets) run on the code,
and on a Python web app the highest-value findings are framework
defaults.

## The failure mode: the starter default that ships

Python's frameworks ship developer-friendly defaults that are unsafe in
production, and a vibe coder rarely flips them:

- `DEBUG = True` left on in Django/Flask leaks stack traces, settings,
  and sometimes a live console to anyone who triggers an error.
- `pickle.load` / `yaml.load` on request data is arbitrary code
  execution. The model reaches for it because it is the shortest
  round-trip; the safe loaders are one detail away (XL-001).
- An f-string built into a `cursor.execute` / Django `.extra` /
  SQLAlchemy `text()` is injection (XL-002).
- `verify=False` on a `requests` call disables TLS for that call and
  every copy of it that gets pasted around (XL-004).
- A key assigned in `settings.py` instead of read from the environment
  is a committed secret (XL-006).

## When the shape is fine

Python is the right shape for backends, data work, and tooling. It is
safe when the framework's production checklist is actually run
(`DEBUG` off, allowed hosts set), untrusted data is never `pickle`d,
queries are parameterized, and secrets come from the environment.

## Related

- [Unsafe deserialization](/learn/patterns/xl-unsafe-deserialization)
  and [Raw query interpolation](/learn/patterns/xl-raw-query-interpolation)
  are the two that most often ship in vibe-coded Python.
