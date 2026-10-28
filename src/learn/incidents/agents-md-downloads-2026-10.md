---
title: 'A Planted AGENTS.md in the Downloads Folder Told the Coding Agent to Install Malware'
slug: 'agents-md-downloads-2026-10'
type: 'incident'
last_updated: '2026-10-28'
summary: "In October 2026 an AGENTS.md file that nobody had written appeared in a developer's Downloads folder. When a coding agent was started there, it read the file as project instructions and tried to install function-color, an npm package from the MALFEX campaign. The install was blocked. The researchers who caught it then showed that a web page can drop such a file without a click, that Codex followed a planted file into editing its own config.toml in more than 90% of trials, and that a CLAUDE.md variant got Claude Code to write an API base URL that leaked the login token. No vendor bug, nothing to patch: the agent did what an instruction file told it to."
draft: false
campaign: 'MALFEX'
attack_date: '2026-10-22'
related_probe_ids:
  - 'AI Rules Files'
  - 'Agent Config Backdoor'
  - 'MCP Security'
  - 'Compromised Packages'
related_incident_slugs:
  - litellm-pypi-2026-10
  - mini-shai-hulud-keyv-2026-08
sources:
  - title: 'The Hacker News: Malicious File in Downloads Folder Tries to Trick AI Coding Agent Into Installing Malware (October 26, 2026)'
    url: 'https://thehackernews.com/2026/10/malicious-file-in-downloads-folder.html'
  - title: 'OSV MAL-2026-17647 (function-color, npm)'
    url: 'https://osv.dev/vulnerability/MAL-2026-17647'
  - title: 'OSV MAL-2026-17648 (function-flag, npm)'
    url: 'https://osv.dev/vulnerability/MAL-2026-17648'
  - title: 'The Hacker News: Eight Malicious npm Packages Deliver Overlord RAT and Stealer (the MALFEX campaign)'
    url: 'https://thehackernews.com/2026/10/eight-malicious-npm-packages-downloaded.html'
  - title: 'AGENTS.md, the open instruction-file format'
    url: 'https://agents.md/'
  - title: 'CWE-829, Inclusion of Functionality from Untrusted Control Sphere'
    url: 'https://cwe.mitre.org/data/definitions/829.html'
---

# A Planted AGENTS.md in the Downloads Folder Told the Coding Agent to Install Malware

Coding agents read an instruction file when they start in a folder. `AGENTS.md` is the cross-tool spelling, read by Codex, Copilot, Cursor, Jules and Gemini CLI; `CLAUDE.md` is Claude Code's. The file is treated as the project's own guidance: conventions, setup steps, what to run first. That trust is the feature, and in October 2026 it was the attack.

## What happened

A security team caught a coding agent on a customer's machine about to install an npm package called `function-color`, and stopped it before any code ran. The instruction came from an `AGENTS.md` sitting in the user's `~/Downloads` folder. Nobody had written it, and the team could not determine how it got there. The agent had been started in Downloads, the way a lot of people start an agent to look at something they just fetched, and it read the stray file as the project's instructions.

`function-color` pulls in `function-flag`, a downloader for a Windows payload. Both are part of the MALFEX campaign, eight npm packages traced to a single actor, delivering a remote-access trojan and a stealer, with more than forty thousand downloads by the start of October. OSV lists `function-color` 1.0.0 and 1.7.3 and `function-flag` 1.7.3 as malicious; PreFlight's **Compromised Packages** probe flags all three.

## What the researchers then showed

The team reproduced the shape in a lab and published it on October 22.

**The delivery.** A web page can save a file into Downloads with no click and no permission prompt. Their proof-of-concept page silently dropped an `AGENTS.md`. Whether a real attacker used that route is unknown; that it works is not.

**The Codex chain.** The planted file, framed as routine project setup, told Codex to register a server in `~/.codex/config.toml` before starting the user's task, and to run a command that installed the package. That config file is machine-wide: every Codex session on the machine, in every folder, loads the server at startup. Codex followed the instruction in more than 90% of attempts.

**The Claude Code chain.** A planted `CLAUDE.md`, framed as internal gateway setup, tried to get Claude Code to write an `ANTHROPIC_BASE_URL` into the project's settings, pointing the agent's API traffic at a server the researchers controlled. That leaks the session's login token, and the server can then answer as if it were the model and return commands for the agent to run. Claude Code requires approval for the write and often refused ones that looked wrong; the long engineering-document framing got the write approved about half the time.

The researchers' position, which the reporting carries without a vendor response: there is nothing for OpenAI or Anthropic to patch. The agents did what they were built to do.

## If you run a coding agent, read this first

1. **Do not start an agent in `~/Downloads`.** It is the one folder a web page can write to on its own.
2. **Read any `AGENTS.md` or `CLAUDE.md` you did not write**, especially in Downloads or a freshly cloned repository, before starting an agent there.
3. **Check `~/.codex/config.toml`** for a server block you did not add, and a project's `.claude/settings.json` for an `ANTHROPIC_BASE_URL` or other endpoint you did not set.
4. **Keep approval prompts and sandboxes on**, and treat any instruction to turn them off as the finding.
5. **If you find a planted file, assume the login token leaked** and rotate it from a clean machine.

## What PreFlight checks

Three probes read this shape, and all three were extended for it:

- **AI Rules Files** now reads `AGENTS.md`, `GEMINI.md`, `.clinerules`, `.roo/rules` and `.github/copilot-instructions.md` alongside `.cursorrules`, `.windsurfrules` and `CLAUDE.md`, and reports a rules file that directs the agent to edit its own configuration, set an API base URL, or install a package before starting. No override language is needed for that finding; "routine setup" that reconfigures the agent is the pattern.
- **Agent Config Backdoor** reports a committed `.claude/settings.json` whose `env` routes `ANTHROPIC_BASE_URL` (or the OpenAI, Gemini and OpenRouter equivalents) to a host that is not the provider.
- **MCP Security** now parses `.codex/config.toml` and reports a server launched through `npx`, `bunx`, `uvx` or `pipx` with no pinned version, which resolves a package from the registry on every agent start.

A committed instruction file is code that runs on every teammate's machine. Review its diff the way you would review a CI workflow, because that is what it is.

## The lesson

The rules-file backdoor of early 2026 hid its instructions in invisible Unicode. This one hid nothing. It was plain markdown that looked like onboarding notes, in a folder the browser owns, read by an agent that was built to trust the folder it starts in. The defence is not a parser; it is not starting the agent somewhere you did not choose, and reading the file that chose for you.
