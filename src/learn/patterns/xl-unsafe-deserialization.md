---
title: Unsafe deserialization (XL-001)
slug: xl-unsafe-deserialization
type: pattern
last_updated: 2026-05-15
draft: false
related_probe_ids:
  - Python Unsafe Deserialization
sources:
  - title: CWE-502 — Deserialization of Untrusted Data
    url: https://cwe.mitre.org/data/definitions/502.html
  - title: OWASP A08 — Software and Data Integrity Failures
    url: https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
  - title: Python pickle docs — security warning
    url: https://docs.python.org/3/library/pickle.html
  - title: PyTorch torch.load weights_only default change
    url: https://pytorch.org/docs/stable/generated/torch.load.html
summary: A deserializer that reconstructs arbitrary objects from bytes is remote code execution the moment those bytes come from a request, a socket, or an uploaded file. The shared cross-language family is XL-001; the language adapters differ only in which call to look for.
---

## What this is

Some deserializers do not just parse data. They reconstruct arbitrary
objects, and reconstructing an object can run code. When the bytes are
something you wrote and stored yourself, that is fine. When the bytes
arrive from a request body, a queue, a cache, or a file a user uploaded,
the deserializer is an arbitrary-code-execution primitive.

The pattern is the same in every language. Only the call changes:

- Python: `pickle.load` / `pickle.loads`, `dill`, `joblib.load`,
  `pandas.read_pickle`, `torch.load(..., weights_only=False)`,
  `yaml.load` without a safe loader.
- Java: `ObjectInputStream.readObject`, `XMLDecoder`.
- Ruby: `Marshal.load`, `YAML.load`.
- PHP: `unserialize` on request data.
- C#: `BinaryFormatter`, `TypeNameHandling != None`.

That cross-language sameness is why this is a shared family (XL-001) with
one concept page and per-language detectors, rather than a dozen
unrelated rules.

## Why AI emits it

Assistants treat deserialization as generic persistence. Asked to
"serialize this object," the model reaches for the language-native API
without asking where the bytes come from. ML tutorials use `pickle` for
model artifacts, so the assistant generalizes the artifact pattern onto a
request body. The training corpus also predates the secure defaults
(PyTorch 2.6's `weights_only=True`, `safetensors`, `yaml.safe_load`), so
the model reproduces the old unsafe form.

## The mental model that produces the bug

"Save object, load object." There is no concept of a trust boundary
between bytes you wrote and bytes a stranger sent. The same call that
round-trips your own cache gets reused on `request.data` because, at the
call site, both are just bytes.

## What the fix looks like

Use a format that parses data without constructing arbitrary objects.

- Data: JSON. `json.loads(request.data)` cannot execute code.
- ML models: `safetensors`, or `torch.load(path, weights_only=True)`.
- YAML: `yaml.safe_load(data)`, or an explicit `Loader=SafeLoader`.

If you genuinely must accept a serialized object graph from outside, the
honest answer is "do not". There is no safe configuration of `pickle`
against untrusted input. Restructure so the boundary carries data, and
the object is built on your side from validated fields.

## Related

- [Raw query interpolation](/learn/patterns/xl-raw-query-interpolation)
  is the same trust-boundary blindness applied to SQL strings.
