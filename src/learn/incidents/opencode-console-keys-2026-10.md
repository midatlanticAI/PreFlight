---
title: 'OpenCode Console: Provider API Keys Stored Server-Side, and the Server Was Breached'
slug: 'opencode-console-keys-2026-10'
type: 'incident'
last_updated: '2026-10-28'
summary: "Overnight on October 16 to 17, 2026 an attacker got into a legacy part of the OpenCode Console, the hosted side of the open-source coding agent, and may have taken the third-party provider keys stored in users' workspaces. OpenCode said 1.4% of Console users were affected, all of them people who had linked an external provider, and told them to revoke and replace the keys and review usage for charges. The agent on the laptop was never involved; the key custody was."
draft: false
campaign: 'OpenCode Console breach'
attack_date: '2026-10-17'
related_probe_ids:
  - 'Secret Scanner'
related_incident_slugs:
  - litellm-pypi-2026-10
sources:
  - title: "TechCrunch: Hackers hit AI coding tool OpenCode, running up charges on users' AI accounts (October 19, 2026)"
    url: 'https://techcrunch.com/2026/10/19/hackers-hit-ai-coding-tool-opencode-running-up-charges-on-users-ai-accounts/'
  - title: "Axios: OpenCode breach exposes AI's cyber defense dilemma (October 21, 2026)"
    url: 'https://www.axios.com/2026/10/21/when-ai-models-refuse-to-fight-hackers'
  - title: 'CWE-522, Insufficiently Protected Credentials'
    url: 'https://cwe.mitre.org/data/definitions/522.html'
---

# OpenCode Console: Provider API Keys Stored Server-Side, and the Server Was Breached

OpenCode is an open-source coding agent; the Console is the hosted service around it, where a user can link their own OpenAI, Anthropic or Google account so the agent bills against it. Linking means the Console holds the key. On October 17, 2026, OpenCode said an intruder had reached part of that platform, a legacy system it was already preparing to retire, during the night of the 16th.

What OpenCode stated: 1.4% of Console users were affected, every one of them a user with an external provider linked; third-party keys stored in those users' workspaces may have been exposed; affected users were emailed the next morning and told to revoke and replace the keys, update anything that depended on them, and check provider usage for charges they did not make. OpenCode connected the intrusion to a large-scale model distillation operation and said it was working with Anthropic, OpenAI and Google.

What OpenCode did not state, as of this writing: how the attacker got in, how long they were inside, or how many keys were involved. Several outlets reported users seeing unauthorised activity and unexpected charges on linked accounts; that is consistent with the advice OpenCode gave and is not something OpenCode confirmed. The distillation link is OpenCode's own characterisation, offered without technical evidence.

## If you linked a provider to a hosted agent, read this first

1. **Revoke the key at the provider**, not just unlink it in the tool. A stolen copy does not know it was unlinked.
2. **Check usage.** Every provider dashboard shows spend by key; a key you revoked that kept spending until the moment of revocation was in use by someone else.
3. **Set spend limits on the replacement.** Provider dashboards support hard caps per key. A cap turns "they ran up my bill" into "they hit the ceiling".
4. **Count the places your key lives.** Each hosted tool you linked is a copy you do not control. The number of copies is your exposure.

## Why this is in a field report for a scanner

PreFlight has an opinion about key custody and it is enforced by architecture rather than policy: a key you give the Explain feature goes from your browser to the provider's documented endpoint and never to PreFlight's origin, because PreFlight has no origin to send it to. That is not a feature list; it is the reason this incident could not happen here, and it is the question to ask any tool that offers to hold a key for you: where does it go, who can read it there, and what is the blast radius when that server has a bad night.

The **Secret Scanner** covers the other half of the same custody problem, the key that ends up in the repository. A key in a hosted workspace and a key in a committed `.env` are the same mistake with different owners.

## The lesson

The agent was never compromised. The laptop was never compromised. A convenience, link your provider once and forget it, put the key on a server with a legacy component, and the legacy component was the way in. The response is cheap and specific: revoke, cap, and count the copies.
