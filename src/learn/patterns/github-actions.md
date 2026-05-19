---
title: Unsafe GitHub Actions workflows
slug: github-actions
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - GitHub Actions
sources:
  - title: GitHub Docs — Security hardening for GitHub Actions
    url: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
  - title: GitHub Docs — Using third-party actions
    url: https://docs.github.com/en/actions/learn-github-actions/finding-and-customizing-actions
  - title: CWE-829 — Inclusion of Functionality from Untrusted Control Sphere
    url: https://cwe.mitre.org/data/definitions/829.html
  - title: 'pull_request_target attack pattern (StepSecurity)'
    url: https://www.stepsecurity.io/blog/pull-request-target-best-practices
summary: Two unsafe GitHub Actions patterns: `pull_request_target` workflows that check out untrusted PR code, and actions pinned to mutable refs (branches or tags). Both produce token-theft and supply-chain compromises with regularity.
---

## What this is

**`pull_request_target` checking out PR head:**

```yaml
on: pull_request_target # runs in the BASE repo context with secrets
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }} # untrusted code
      - run: npm test
```

`pull_request_target` runs in the context of the base repository with access to its secrets, on the theory that the workflow file should not be modifiable by the PR. Checking out the PR's head sha means executing whatever the PR author wrote, with the base repo's secrets in `GITHUB_TOKEN` and the repo's other secrets in env. A malicious PR can exfiltrate every secret.

**Mutable ref pinning:**

```yaml
- uses: actions/checkout@main # main is mutable
- uses: actions/checkout@v4 # v4 tag is mutable
- uses: third-party/action@latest # latest is mutable
```

A maintainer of the action (or anyone who compromises the maintainer's account) can update the underlying commit at any time. Every workflow run after the update executes the new code. This is the supply chain attack pattern that has hit `tj-actions/changed-files` and others.

## Why it matters

Both patterns produce arbitrary code execution in a workflow that holds repo secrets and a `GITHUB_TOKEN` with write access. The blast radius includes:

- Every secret in the repository (`secrets.*` plus any env vars the workflow sets).
- The ability to push to any branch the `GITHUB_TOKEN` can write to, including production.
- The cached dependencies of the workflow, which can be poisoned for subsequent runs.
- The signed releases and packages the workflow produces.

Several 2024-2026 incidents started here. A compromised action, executed in a privileged workflow, exfiltrated tokens that the attacker then used to publish poisoned npm packages downstream.

## What the failure looks like

PreFlight scans `.github/workflows/*.yml` for:

- `on: pull_request_target` workflows that include `uses: actions/checkout` with `ref:` pointing at `github.event.pull_request.head.sha` or similar untrusted-PR-code references.
- `uses: <org>/<action>@<ref>` where `<ref>` is not a 40-character SHA. Branches (`@main`, `@master`) and tags (`@v4`, `@latest`) are mutable refs and produce the finding.

## What the fix looks like

**Pin every action to a SHA, not a tag or branch.**

```yaml
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.7
```

Use the comment to track which tag the SHA corresponds to. Bots like `dependabot` can update the SHA + comment together when the maintainer publishes a new tag, giving you the supply-chain pin without the manual lookup.

**For `pull_request_target` workflows that need to interact with PR code, separate the privileged step from the PR-code step.**

```yaml
on: pull_request_target

jobs:
  # Privileged step: runs in base context with secrets, but does NOT check out PR code.
  comment-pr:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@<sha>
        with:
          script: |
            github.rest.issues.createComment({ ... });

  # Untrusted step: checks out the PR code but has no secrets.
  test-pr:
    runs-on: ubuntu-latest
    permissions:
      contents: read # minimal permissions; no token write access
    steps:
      - uses: actions/checkout@<sha>
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test # runs in an isolated job with no secrets
```

The two-job pattern keeps the credentials out of any job that executes PR code.

## Related

- [package.json supply-chain hooks](/learn/patterns/package-json-supply-chain) covers the parallel pattern on the npm side.
- [Malicious artifacts](/learn/patterns/malicious-artifacts) covers post-infection indicators that show up when a workflow compromise has already happened.

## Sources

GitHub's security hardening guide is the authoritative reference for workflow hardening. The CWE-829 entry covers the underlying class. The StepSecurity blog post on `pull_request_target` is one of the clearest published walkthroughs of the attack pattern.
