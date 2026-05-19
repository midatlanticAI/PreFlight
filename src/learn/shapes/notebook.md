---
title: Notebook / data-science codebase
slug: notebook
type: shape
last_updated: 2026-05-15
draft: false
related_probe_ids:
  - Architecture
related_incident_slugs: []
sources:
  - title: CWE-798 — Use of Hard-coded Credentials
    url: https://cwe.mitre.org/data/definitions/798.html
  - title: CWE-502 — Deserialization of Untrusted Data
    url: https://cwe.mitre.org/data/definitions/502.html
summary: A codebase dominated by .ipynb files. Notebooks invite the exact habits that leak: a key pasted into a cell, an output committed with data in it, a model file loaded from anywhere.
---

## What this shape is

A project where Jupyter notebooks dominate. The classifier reports it as
Notebook / Data Science when two or more `.ipynb` files are present.

## Scanner behavior

PreFlight classifies this shape (informational). It does not raise a
shape-specific finding for it; the secret and deserialization probes
still run, and notebooks are exactly where their patterns show up.

## The failure mode: the notebook is a trap for good habits

The notebook workflow rewards the shortcuts that cause leaks:

- A key pasted into a cell to "just get it working" is a hardcoded
  secret (XL-006), and notebooks are committed with that cell intact
  far more often than source files are.
- Cell outputs are saved in the file. A printed dataframe, an API
  response, a token echoed for debugging: all committed into the
  `.ipynb` and into git history.
- `pickle.load` / `torch.load` / `joblib.load` of a model or cache from
  an untrusted path is code execution (XL-001); the data-science corpus
  treats these as routine.
- Notebooks rarely pin dependencies, so the environment that ran is not
  the environment that reruns, and a swapped or typosquatted package
  executes in it.

## When the shape is fine

Notebooks are the right tool for exploration and analysis. They are
safe when secrets come from the environment (not a cell), outputs are
cleared before commit, model and cache files load only from trusted
constant paths, and the environment is pinned. Exploration is not an
excuse to skip the boundary; it is where the boundary is easiest to
forget.

## Related

- [Hardcoded secrets and policy text](/learn/patterns/xl-hardcoded-secrets)
  and [Unsafe deserialization](/learn/patterns/xl-unsafe-deserialization)
  are the two that ship in notebooks most.
