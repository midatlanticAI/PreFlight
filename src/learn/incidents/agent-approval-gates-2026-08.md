---
title: 'The approval prompt is the whole security model, and it kept not firing'
slug: 'agent-approval-gates-2026-08'
type: 'incident'
last_updated: '2026-08-27'
draft: false
summary: 'Between August 10 and August 26, 2026, six products that run coding agents published advisories describing the same failure. A tool call that was supposed to stop and ask a human did not stop. VS Code, Cursor, Continue CLI, CodeWhale, Amazon Strands and goose each shipped a way for an agent to reach the shell, the filesystem or a privileged container without the consent gate firing. This is a field report about why that gate carries more weight than it can hold, and what bounds the damage when it fails.'
campaign: 'Agent consent-gate bypass'
attack_date: '2026-08-11'
related_probe_ids:
  - 'Agent Config Backdoor'
  - 'MCP Security'
  - 'AI Rules Files'
  - 'Compromised Packages'
sources:
  - title: 'GHSA-w79w-rj9h-vg4f, VS Code Copilot custom agent hook RCE (CVE-2026-70335)'
    url: 'https://github.com/microsoft/vscode/security/advisories/GHSA-w79w-rj9h-vg4f'
  - title: 'GHSA-3hjg-cwxj-qfc6, Copilot Chat security feature bypass (CVE-2026-65675)'
    url: 'https://github.com/microsoft/vscode/security/advisories/GHSA-3hjg-cwxj-qfc6'
  - title: 'CVE-2026-73217, Cursor Auto-Run sandbox escape via tampered virtualenv'
    url: 'https://www.cve.org/CVERecord?id=CVE-2026-73217'
  - title: 'CVE-2026-73218, Cursor sandbox escape via privileged container'
    url: 'https://www.cve.org/CVERecord?id=CVE-2026-73218'
  - title: 'GHSA-xqr4-4xjv-5j7q, Continue CLI unattended Bash permission (CVE-2026-76072)'
    url: 'https://github.com/advisories/GHSA-xqr4-4xjv-5j7q'
  - title: 'CVE-2026-72718, goose review runs attacker git config'
    url: 'https://www.cve.org/CVERecord?id=CVE-2026-72718'
  - title: 'GHSA-4qch-7gcj-fhvm, remote-claude-daemon (OSV MAL-2026-13455)'
    url: 'https://github.com/advisories/GHSA-4qch-7gcj-fhvm'
  - title: 'CVE-2026-75149, marimo notebook MCP command execution'
    url: 'https://www.cve.org/CVERecord?id=CVE-2026-75149'
  - title: 'CWE-862, Missing Authorization'
    url: 'https://cwe.mitre.org/data/definitions/862.html'
---

## What happened

Between August 10 and August 26, 2026, six products that run coding agents
published advisories describing the same failure. A tool call that was supposed
to stop and ask a human did not stop.

Microsoft published nine security advisories against microsoft/vscode on August
11 and 12, all fixed in VS Code 1.132.1. Two are about consent. Under
CVE-2026-70335 (GHSA-w79w-rj9h-vg4f), a crafted prompt injection could make the
Copilot agent write custom agent files carrying lifecycle hooks, with no
confirmation dialog. The hooks then run as the user when that agent is invoked.
Under CVE-2026-65675 (GHSA-3hjg-cwxj-qfc6), the Claude integration bundled in
the Copilot Chat extension honoured the "Edit automatically" permission mode for
files outside the workspace, which is to say anywhere on disk.

Continue CLI, CVE-2026-76072 (GHSA-xqr4-4xjv-5j7q), published August 24. When
running unattended, the default policy grants the Bash tool the allow
permission, leaving a dangerous-path denylist as the sole control. That list
matches `/`, `/*`, `~`, `~/*`, `/usr`, `/etc`, `/bin` and `/sbin`, and not
`/home`, `/root`, `/var`, `/opt` or `/srv`. The command line is parsed with a
shell-quote library that reduces `$HOME` to an empty token, so `rm -rf $HOME`
passes the dangerous-path test while the shell re-expands the variable at spawn
time. As of this writing no fixed version has been published and no vendor
security advisory exists, so unattended use of that tool has nothing to upgrade
to yet.

CodeWhale, three CVEs, affecting codewhale and codewhale-tui from 0.8.41 up to
but not including 0.8.64, which is the fixed release. The rlm_eval tool's
`approval_requirement()` returns `Auto`, which the engine treats as never
prompt, so model-supplied code runs without consulting the approval policy
(CVE-2026-75858). exec_shell_interact does the same, overriding the `Required`
default for code-executing tools (CVE-2026-75857). And the model-supplied `rev`
parameter of the git_show tool reaches the `git show` argument list with no
end-of-options sentinel, so a flag-shaped value is parsed as a flag, which turns
a tool registered as read-only into a file write (CVE-2026-75913). In Amazon
Strands Agents Tools, fixed in 0.8.5, a prompt forwarding `non_interactive_mode`
as a keyword argument through the batch tool bypasses the `python_repl` consent
gate (CVE-2026-78379).

Cursor's two macOS sandbox advisories both have CVE records published August 11.
CVE-2026-73217, fixed in 3.1.2, lets an agent in Auto-Run Sandbox mode replace a
virtual environment's Python executable with a wrapper that the Microsoft Python
extension then invokes outside the sandbox, running host commands.
CVE-2026-73218, fixed in 3.0.0, covers an agent launching a privileged container
that mounts Docker's virtiofs0 and reaches the home directory with no further
prompt.

goose, CVE-2026-72718, fixed in 1.44.0. `goose review` runs the system git to
gather a diff without stripping attacker-controlled git configuration, so a
repository whose `.git/config` sets `[core] fsmonitor = <command>` gets that
command run during the index refresh. The advisory is explicit that this happens
before goose contacts a model: no submitted prompt, no model call, no tool
approval, no trust prompt.

Two more from the same weeks arrive from the package ecosystem rather than from
the agent products. The npm package remote-claude-daemon
(GHSA-4qch-7gcj-fhvm, OSV MAL-2026-13455) flags twenty versions between 0.3.0
and 0.6.6. It connects to a hardcoded WebSocket relay and, on inbound messages,
spawns the local `claude` binary with `--continue -p
--dangerously-skip-permissions` and a remote-supplied prompt. And marimo before
0.23.15 (CVE-2026-75149) allows a shared notebook to carry an MCP server entry
whose `command` value is launched when the notebook is opened in edit mode.

## Why this shape keeps working

A denylist of dangerous paths is a speed bump. Continue's list is a sensible
one, it still omits `/home`, and the parser it relies on disagrees with the
shell about what `$HOME` means. Every denylist inherits the quoting and
expansion differences between the thing that checks and the thing that executes.

An allowlist that reads the program name and ignores the arguments is not a
check. `git show` is a read. `git show` handed an output option is whatever that
option does, which is why the `--end-of-options` sentinel exists.

Agent configuration files are executable content, not settings. Lifecycle hooks,
custom agent definitions, MCP server entries and git config keys all resolve to
a command line that some tool runs on a trigger the user never pressed. goose is
the clearest case: the command ran before the model was contacted at all.

Underneath all of it, the consent prompt carries the whole security model alone.
Unattended and auto modes are how people actually run coding agents, and that
prompt is the only thing between an instruction the agent read in a web page or
a repository file and a command on the machine. What bounds the damage is the
account and the filesystem the agent runs as: a separate user, a container that
does not mount the home directory, credentials that are not in the environment
it inherits.

## What to check in your own project

Update first. VS Code to 1.132.1, Cursor to 3.1.2, goose to 1.44.0, Strands
Agents Tools to 0.8.5, CodeWhale to 0.8.64. Continue CLI has no published fixed
version, so unattended use of that tool has nothing to move to yet.

Then, in each repository an agent touches:

```bash
# 1. git config keys that execute a command, and committed steps that set them
git config --get core.fsmonitor; git config --get core.pager; git config --get core.hooksPath
grep -rn "fsmonitor\|hooksPath\|core\.pager" .devcontainer .github Dockerfile* scripts 2>/dev/null

# 2. permission bypass wired into automation
grep -rn -- "--dangerously-skip-permissions" package.json scripts .github Dockerfile* 2>/dev/null
grep -n "remote-claude-daemon" package.json package-lock.json 2>/dev/null

# 3. instruction and agent config files, and who changed them
git log --oneline -20 -- AGENTS.md CLAUDE.md .cursorrules .claude .vscode/tasks.json .mcp.json
```

Read AGENTS.md and CLAUDE.md end to end. They load as instructions at the start
of every run, so a paragraph nobody asked for changes what the agent does before
the first prompt. A repository that arrives as an archive or on a shared volume
brings its own `.git/config`, so open that file before running any agent command
inside it.

## What PreFlight does about it

The **Agent Config Backdoor** probe reads committed `.claude/settings.json`,
`.claude/settings.local.json` and `.vscode/tasks.json`, and reports any hook
wired to an auto-firing event and any task with `runOn: folderOpen`, whether or
not the command looks malicious. The Copilot custom agent files behind
CVE-2026-70335 are not in that file set, so PreFlight does not see them today.

The **MCP Security** probe parses `claude_desktop_config.json`, `.mcp.json` and
`mcp.json`, and flags server entries that spawn a shell interpreter with `-c`,
`-e` or `-Command`, plus mcp-server-git and servers bound to 0.0.0.0. An MCP
entry embedded in a marimo notebook is not one of those filenames, so it falls
outside.

The **AI Rules Files** probe checks `.cursorrules`, `.cursor/rules/`,
`.windsurfrules` and `CLAUDE.md` for bidirectional control characters and
instruction-override phrasing. AGENTS.md is not in that set, which is why the
check above says to read it yourself. **Compromised Packages** matches
package.json and lockfile versions against the threat-intel manifest, last
reviewed 2026-08-07, and remote-claude-daemon is not in it today, so grep the
lockfile by hand.

Two honest gaps. No probe matches `--dangerously-skip-permissions` or
`core.fsmonitor`, and `.git/` is excluded from scanning, so PreFlight never sees
a repository's own `.git/config`. And PreFlight scans repositories, not installed
applications, so it cannot tell you which VS Code, Cursor or goose build is on
the machine. The version updates at the top of the previous section are a manual
step, and the grep commands are there because the probes do not yet cover this
whole surface.
