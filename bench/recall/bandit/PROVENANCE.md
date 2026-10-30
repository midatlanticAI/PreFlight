# Vendored sample provenance

These two examples and `LICENSE` are unmodified bytes from
[PyCQA/bandit at 48ef27bd1bbc32f4e585c92310f7a574e87f6b04](https://github.com/PyCQA/bandit/tree/48ef27bd1bbc32f4e585c92310f7a574e87f6b04).
Copyright remains with the upstream authors/contributors. Distributed under
Apache-2.0; the complete upstream license is included beside the examples.
No upstream NOTICE file existed at this revision (contents API returned 404).
No upstream detection implementation or rule has been vendored.

| File                              | Upstream Git blob SHA-1                    |
| --------------------------------- | ------------------------------------------ |
| `yaml_load.py`                    | `a6a2eb164027ba7fa7494b12de4aaeb7a920f751` |
| `requests-ssl-verify-disabled.py` | `c45b9e944731eb49f709bc52bec288ba4cd4911d` |
| `LICENSE`                         | `67db8588217f266eb561f75fae738656325deac9` |

Label evidence, pinned to that same revision:

- [B506 documentation and policy](https://github.com/PyCQA/bandit/blob/48ef27bd1bbc32f4e585c92310f7a574e87f6b04/bandit/plugins/yaml_load.py): unsafe YAML object construction. The upstream functional `test_yaml` expects two medium findings. Explicit safe-case comments support the negative labels. The manifest maps the broad upstream CWE-20 to the narrower CWE-502 class for this particular operation. This is a declared label mapping, never a generic scorer alias.
- [B501 documentation and policy](https://github.com/PyCQA/bandit/blob/48ef27bd1bbc32f4e585c92310f7a574e87f6b04/bandit/plugins/crypto_request_no_cert_validation.py): HTTPS calls and clients with `verify=False`, including httpx, are positive; default/true verification is negative. The example's historical `# Okay` heading does not override that policy for httpx.
- [Functional expectations](https://github.com/PyCQA/bandit/blob/48ef27bd1bbc32f4e585c92310f7a574e87f6b04/tests/functional/test_functional.py).

Line labels were transcribed locally from these external expectations before
running PreFlight, not generated from PreFlight findings. Their source is
independent of PreFlight, but this is not independent human adjudication and
no upstream tool was executed for this baseline. These are synthetic risky API
examples, not demonstrated exploitable applications. Some calls depend on
legacy PyYAML/httpx signatures. No vulnerable Python code is executed.

Only these two small examples and their license were retrieved. There is no
bulk corpus checkout and subsequent runs require no network access.
