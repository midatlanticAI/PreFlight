---
title: 'LiteLLM 1.107.0: A Release Pipeline Taken Over, a Stealer That Runs on Every Python Start'
slug: 'litellm-pypi-2026-10'
type: 'incident'
last_updated: '2026-10-28'
summary: "On October 21, 2026 an attacker holding three LiteLLM developers' GitHub CLI credentials overrode branch protection, pointed the release workflow at a lookalike repository, and published litellm 1.107.0 to PyPI and Docker Hub. The wheels drop cook.pth, cook.py and sitecustomize.py into site-packages, so every Python process on the host reruns a credential stealer, pip included, and the payload targets cloud credentials, SSH keys, and the auth files of AI coding tools. PyPI pulled it after 1 hour 43 minutes; the hosts that installed it in that window are the incident."
draft: false
campaign: 'LiteLLM pipeline compromise'
attack_date: '2026-10-21'
related_probe_ids:
  - 'Compromised Packages'
  - 'Secret Scanner'
related_incident_slugs:
  - mini-shai-hulud-keyv-2026-08
  - agents-md-downloads-2026-10
sources:
  - title: 'LiteLLM incident report: Oct 21, 2026 release v1.107.0 compromised (victim postmortem)'
    url: 'https://docs.litellm.ai/blog/security-incident-oct-21-2026'
  - title: 'OSV MAL-2026-2144 (litellm, PyPI)'
    url: 'https://osv.dev/vulnerability/MAL-2026-2144'
  - title: 'The Hacker News: LiteLLM Compromised in Supply Chain Attack Delivering Credential Stealer and Backdoor'
    url: 'https://thehackernews.com/2026/10/litellm-compromised-in-supply-chain.html'
  - title: 'CWE-506, Embedded Malicious Code'
    url: 'https://cwe.mitre.org/data/definitions/506.html'
---

# LiteLLM 1.107.0: A Release Pipeline Taken Over, a Stealer That Runs on Every Python Start

LiteLLM is the proxy a great many AI apps put between themselves and their model providers; its database holds the provider keys for every model it fronts. On October 21, 2026, its release pipeline published a version that steals exactly those.

The timeline, from LiteLLM's own report, all UTC:

- **10:08:29** GitHub branch protection rejects an unauthorised change to the private release workflow.
- **10:08:34** Five seconds later a privileged developer credential, belonging to an organisation owner, disables the protection and applies the change.
- **10:46** A staging run builds from an attacker-controlled lookalike repository, `Berri-AI/litellm`.
- **11:11** A second developer credential satisfies the production approval gate.
- **11:39 to 11:40** Seven malicious `litellm==1.107.0` wheels upload to PyPI.
- **11:46** Container jobs publish the Docker image; `v1.107.0`, `latest`, `main-latest` and `main-stable` all point at it.
- **11:53** A third developer credential deletes the production and staging workflow records.
- **13:23** PyPI removes the release. Docker Hub tags are repointed by 14:20.

The official `v1.107.0` source tag in GitHub never contained the malicious files. The artefacts did.

## If you installed it, read this first

LiteLLM's instructions, in their order:

1. **Do not run `pip install` first.** The payload reruns on every Python start, and pip is a Python start.
2. **Remove the persistence.** In every affected site-packages: `cook.pth`, `cook.py`, `sitecustomize.py`, and the matching `__pycache__/cook*.pyc` and `sitecustomize*.pyc`.
3. **Kill the daemon.** A detached Python process holds `/tmp/remote_code_loader.lock`.
4. **Rebuild.** Pin `litellm==1.106.2` at minimum; LiteLLM recommends rebuilding images and virtualenvs from scratch.
5. **Assume exfiltration if the host had outbound internet.** A marker file can confirm it; its absence proves nothing.
6. **Rotate everything the host could reach:** the instance or task IAM role, every provider key in the LiteLLM proxy database plus master and virtual keys, the `DATABASE_URL` password, and any secret in the environment of any process on the host.
7. **Audit.** CloudTrail for `GetCallerIdentity` from the instance role around install time, and for use of those credentials from outside your infrastructure.

Independent analysis of the wheels adds what the postmortem leaves out: the stealer collects SSH private keys, AWS, GCP and Azure credentials, browser passwords, and the configuration and token files of more than twenty AI coding tools, and posts the encrypted bundle to a host named to look like LiteLLM's own infrastructure.

PreFlight's **Compromised Packages** probe now reads `requirements*.txt`, `poetry.lock`, `uv.lock` and `Pipfile.lock` and flags `litellm` at 1.107.0, and at 1.82.7 and 1.82.8 from the March 2026 incident on the same package.

## How the attacker got in

Three sets of developer GitHub CLI credentials. LiteLLM found an unexpected user account on an internal deployment that was exposed to the internet and believes the OAuth tokens were lifted from that deployment's logs. The report notes that a coding agent can embed a user's GitHub CLI token in a response body, and response bodies get logged.

Read that twice. The credentials that signed a malicious release were not phished and not guessed. They were in a log file of an LLM proxy, because something that talked to the proxy had a token in its context and the proxy logged what it saw. The March incident had already made LiteLLM harden its CI; this one went through the hardened pipeline on legitimate credentials, each gate satisfied by a different stolen token.

## What this has in common with the npm worms

The same lesson as the August keyv wave, in a different ecosystem: the persistence outlives the package. `pip uninstall litellm` leaves `sitecustomize.py` in place, and Python imports `sitecustomize` on every start without being asked. The npm worms used a Claude Code SessionStart hook for the same effect. The mechanism is always something the host runs automatically, and the response always starts with removing that, not with rotating keys from the infected machine.

## The lesson

Two, really. First: a proxy that holds every provider key is the highest-value box in the architecture, and its logs are part of that box. Scrub tokens before they land in a log, or do not log bodies. Second: pin and verify. A `requirements.txt` with `litellm>=1.100` would have pulled 1.107.0 in the window; a lockfile with a hash would not have, and would have failed loudly on the rebuilt wheel. PreFlight reports the exact pin; the lockfile is what keeps the pin honest.
