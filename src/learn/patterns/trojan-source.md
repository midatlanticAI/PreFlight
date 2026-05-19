---
title: Trojan Source (bidi Unicode in code)
slug: trojan-source
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - Trojan Source
  - AI Rules Files
sources:
  - title: 'Trojan Source paper (Boucher & Anderson, 2021)'
    url: https://trojansource.codes/
  - title: 'CVE-2021-42574 — Bidirectional Override Vulnerability'
    url: https://nvd.nist.gov/vuln/detail/CVE-2021-42574
  - title: 'CWE-1007 — Insufficient Visual Distinction of Homoglyphs'
    url: https://cwe.mitre.org/data/definitions/1007.html
  - title: 'Unicode Bidirectional Algorithm (TR 9)'
    url: https://unicode.org/reports/tr9/
summary: Source files containing Unicode bidirectional control characters (U+202A-U+202E, U+2066-U+2069). The characters reorder visible text in editors and code review tools, hiding malicious code in plain sight.
---

## What this is

Unicode has bidirectional control characters that change the visual order of text without changing the byte order. They were designed for legitimate use in mixed left-to-right + right-to-left text (English plus Arabic, for example). The bytes:

- `U+202A` LRE (Left-to-Right Embedding)
- `U+202B` RLE (Right-to-Left Embedding)
- `U+202C` PDF (Pop Directional Formatting)
- `U+202D` LRO (Left-to-Right Override)
- `U+202E` RLO (Right-to-Left Override)
- `U+2066`-`U+2069` (isolate variants)

A code review tool that respects Unicode bidi renders the file the way the bidi characters say. The compiler ignores them. The result is a file that looks one way to a human reviewer and means something different to the compiler.

The 2021 Boucher and Anderson paper demonstrated the attack across C, C++, Java, JavaScript, Python, Go, Ruby, and Rust. CVE-2021-42574 was assigned to track the class.

## Why it matters

The blast radius is "every line of code reviewed by a human." A maintainer reviewing a pull request sees `if (admin) { allow(); }` but the file actually contains a hidden bidi sequence that makes the compiler read `if (!admin) { allow(); }`. The review passes. The malicious behavior ships.

For AI-coded apps the risk is amplified one level: AI assistants typically render the file's visible string when summarizing diffs, which means the assistant sees the visually-presented version, not the byte-level reality. A maintainer asking "what does this commit do" gets the human-readable answer that matches what the bidi was trying to obscure.

## What the failure looks like

PreFlight scans every file for the bidi character ranges:

```
U+202A through U+202E
U+2066 through U+2069
```

A hit in any source, config, or documentation file is a finding. There is essentially no legitimate reason for these characters to appear in a code file.

## What the fix looks like

Two motions.

**Remove the bidi characters.** Any decent editor can show them as visible escapes. A `git grep -P '[\x{202A}-\x{202E}\x{2066}-\x{2069}]'` finds every occurrence. Open each, decide whether the bidi was intentional (almost never), and remove it.

**Add a pre-commit / CI block.**

```bash
# pre-commit hook or CI script
if grep -lP '[\x{202A}-\x{202E}\x{2066}-\x{2069}]' $(git diff --cached --name-only --diff-filter=ACM); then
  echo "bidi control character detected in staged changes; refusing commit"
  exit 1
fi
```

ESLint has a `unicode-bom` rule and other linters have bidi-detection plugins. GitHub's web interface highlights bidi characters in diffs since late 2021. The defense layers are now widely available; the only requirement is turning them on.

## Related

- [AI rules files](/learn/patterns/ai-rules-files) covers the specific case of bidi characters in `.cursorrules` / `.windsurfrules` / `CLAUDE.md` files. Same character set, different blast radius (the AI assistant follows the hidden instructions instead of the visible ones).

## Sources

The Trojan Source paper at trojansource.codes is the canonical writeup. CVE-2021-42574 is the tracking record. The Unicode Bidirectional Algorithm (TR 9) is the underlying spec.
