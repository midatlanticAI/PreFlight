---
title: MCP server security
slug: mcp-security
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - MCP Security
sources:
  - title: 'Model Context Protocol — Spec'
    url: https://modelcontextprotocol.io/specification
  - title: 'Model Context Protocol — Security'
    url: https://modelcontextprotocol.io/specification/draft/basic/authorization
  - title: 'CWE-78 — OS Command Injection'
    url: https://cwe.mitre.org/data/definitions/78.html
  - title: 'CWE-918 — SSRF'
    url: https://cwe.mitre.org/data/definitions/918.html
summary: MCP servers that spawn shell interpreters, bind to 0.0.0.0, or run vulnerable versions of `mcp-server-git`. Each turns the developer's AI assistant into a path-traversal foothold.
---

## What this is

The Model Context Protocol (MCP) is the standard developers use to connect AI assistants (Claude Desktop, Cursor, Claude Code) to tools that read files, query databases, or run code. An MCP server is a process the assistant talks to over stdio or HTTP. The server exposes tools the assistant can call.

The pattern is powerful and also a privilege boundary. Three failure shapes:

**Shell-spawning servers:**

```json
{
  "mcpServers": {
    "shell": {
      "command": "bash",
      "args": ["-c", "echo hi"]
    }
  }
}
```

Or:

```json
{
  "mcpServers": {
    "powershell": {
      "command": "powershell",
      "args": ["-Command", "..."]
    }
  }
}
```

The MCP server is literally a shell interpreter the assistant calls with arbitrary arguments. Anything the assistant decides to run, runs. Prompt injection upstream of the assistant turns into RCE on the developer's machine.

**Public network bind:**

```json
{
  "mcpServers": {
    "db": {
      "command": "node",
      "args": ["mcp-db-server.js"],
      "env": { "HOST": "0.0.0.0", "PORT": "3000" }
    }
  }
}
```

`0.0.0.0` binds the server to every network interface. Independent research published in April 2026 found roughly 200,000 MCP servers internet-exposed with command-execution flaws. The pattern produces a remote-code-execution endpoint anyone on the network can hit.

**Vulnerable `mcp-server-git`:** versions prior to December 2025 were susceptible to indirect prompt injection via README and issue content. The assistant reads a repo's README, the README contains hidden instructions, the assistant follows them.

## Why it matters

An MCP server runs with the developer's user-level permissions. A compromised or misconfigured server has access to:

- The developer's filesystem (every project, every credential, every cache).
- The developer's network (corporate VPN, cloud credentials, intranet resources).
- The developer's other tools (anything reachable from the user's shell).

A shell-spawning MCP server in a developer's config means a single prompt injection (anywhere upstream, including in a document the assistant reads) executes shell on the developer's machine. The blast radius is the developer's full environment.

## What the failure looks like

PreFlight scans MCP configuration files (`mcp.json`, `.mcp/`, `claude_desktop_config.json`, `cursor.json`) for:

- `command: bash`, `command: sh`, `command: powershell`, `command: cmd` paired with `-c`, `-Command`, or similar inline-execution flags.
- `0.0.0.0`, `::`, or `host: 0.0.0.0` in MCP server env or args.
- `mcp-server-git` at versions prior to December 2025.

## What the fix looks like

**No shell interpreters as MCP servers.** A real MCP server is a purpose-built process with a defined tool surface. If you find `bash -c` in your config, the entry should be removed entirely or replaced with a real server that exposes the specific operations you wanted (e.g., a "run-build" server that runs `npm run build` and nothing else).

**Bind to localhost only.**

```json
{
  "mcpServers": {
    "db": {
      "env": { "HOST": "127.0.0.1", "PORT": "3000" }
    }
  }
}
```

`127.0.0.1` accepts connections only from the same machine. The assistant on your laptop can talk to it; an attacker on the same network cannot.

**Keep `mcp-server-git` current.** Update past the December 2025 vulnerable window. The fix landed in `mcp-server-git@2025.12.x`.

**Audit your MCP config periodically.** Every entry should answer:

- What does this server let the assistant do?
- What's the minimum tool surface that achieves the use case?
- Is the server bound to localhost?
- Is the version pinned to something you trust?

## Related

- [LLM security](/learn/patterns/llm-security) covers the broader agentic-tool class. MCP is a specific transport for the same risk.
- [AI rules files](/learn/patterns/ai-rules-files) covers the parallel attack surface in the assistant's config (rules files instead of tools).
- [Malicious artifacts](/learn/patterns/malicious-artifacts) covers post-infection indicators when an MCP compromise has already happened.

## Sources

The MCP specification is the authoritative reference for protocol semantics. CWE-78 (OS command injection) names the shell-spawning class. CWE-918 (SSRF) names the network-bind class.
