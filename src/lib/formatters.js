// src/lib/formatters.js
// Result serializers for the four export targets the tool offers:
//   - formatJSON          machine-readable, single-source-of-truth for downstream tooling
//   - formatMarkdown      long-form human-readable (one block per finding, full remediation)
//   - formatPRComment     collapsed <details> block that fits in a GitHub PR review
//   - formatAgentPrompt   instruction-shaped text for pasting into another LLM session
//
// Every export reads the same `results` shape and is pure (no side effects). All
// styling decisions live here so the App component never has to inline ad-hoc string
// templates.

import { SEV_ORDER } from './scoring.js';
import { riskTier } from './theme.js';
import { snippetToText } from './snippet.js';

export function formatJSON(results) {
  return JSON.stringify(
    {
      schema: 'midatlantic-audit/v1',
      scannedAt: results.scannedAt.toISOString(),
      source: results.source,
      filesScanned: results.filesScanned,
      score: results.score,
      riskTier: riskTier(results.score).label,
      summary: {
        total: results.findings.length,
        bySeverity: results.findings.reduce((a, f) => {
          a[f.severity] = (a[f.severity] || 0) + 1;
          return a;
        }, {}),
      },
      findings: results.findings.map((f) => ({
        id: f.id,
        severity: f.severity,
        category: f.category,
        cwe: f.cwe,
        probe: f.probe,
        title: f.title,
        file: f.file,
        line: f.line,
        evidence: f.evidence,
        remediation: f.remediation,
        snippet: f.snippet
          ? {
              startLine: f.snippet.startLine,
              endLine: f.snippet.endLine,
              text: snippetToText(f.snippet),
            }
          : null,
      })),
    },
    null,
    2
  );
}

export function formatMarkdown(results) {
  const tier = riskTier(results.score);
  const sevCounts = results.findings.reduce((a, f) => {
    a[f.severity] = (a[f.severity] || 0) + 1;
    return a;
  }, {});
  const sevLine = SEV_ORDER.filter((s) => sevCounts[s])
    .map((s) => `${sevCounts[s]} ${s}`)
    .join(', ');

  let md = `# Pre-Flight Security Audit\n\n`;
  md += `- **Risk:** ${tier.label} — score ${results.score} / 100\n`;
  md += `- **Source:** ${results.source}\n`;
  md += `- **Files scanned:** ${results.filesScanned}\n`;
  md += `- **Scanned at:** ${results.scannedAt.toISOString()}\n`;
  md += `- **Findings:** ${results.findings.length}${sevLine ? ` (${sevLine})` : ''}\n\n`;
  md += `---\n\n`;

  results.findings.forEach((f, i) => {
    md += `## ${i + 1}. [${f.severity.toUpperCase()}] ${f.title}\n\n`;
    md += `- **File:** \`${f.file}${f.line ? ':' + f.line : ''}\`\n`;
    md += `- **Category:** ${f.category}\n`;
    md += `- **CWE:** ${f.cwe}\n`;
    md += `- **Probe:** ${f.probe}\n\n`;
    md += `**Evidence**\n\n\`${f.evidence}\`\n\n`;
    if (f.snippet) {
      md += `**Code snapshot** (line ${f.line} marked with \`>\`)\n\n`;
      md += '```\n' + snippetToText(f.snippet) + '\n```\n\n';
    }
    md += `**Remediation**\n\n${f.remediation}\n\n---\n\n`;
  });
  return md;
}

// PR-comment Markdown: fits in a collapsed <details> block, links findings by file path, summary tagline.
export function formatPRComment(results) {
  const tier = riskTier(results.score);
  const sevCounts = results.findings.reduce((a, f) => {
    a[f.severity] = (a[f.severity] || 0) + 1;
    return a;
  }, {});
  const top = SEV_ORDER.filter((s) => sevCounts[s]);
  const sevSummary = top.length
    ? top.map((s) => `${sevCounts[s]} ${s}`).join(' · ')
    : 'no findings';
  const titleEmoji = tier.label.startsWith('CRITICAL')
    ? '🟥'
    : tier.label.startsWith('HIGH')
      ? '🟧'
      : tier.label.startsWith('MODERATE')
        ? '🟨'
        : '🟩';

  let md = `## ${titleEmoji} Pre-Flight Audit — ${tier.label} (${results.score}/100)\n\n`;
  md += `**${results.findings.length} finding${results.findings.length === 1 ? '' : 's'}** · ${sevSummary} · ${results.filesScanned} file${results.filesScanned === 1 ? '' : 's'} scanned\n\n`;
  if (results.findings.length === 0) {
    md += '_No findings from this probe set. Manual IDOR / runtime checks remain out of scope._\n';
    return md;
  }
  md += `<details>\n<summary>Click to expand ${results.findings.length} finding${results.findings.length === 1 ? '' : 's'}</summary>\n\n`;
  // Group by file so the comment shows up next to the code review naturally.
  const byFile = new Map();
  results.findings.forEach((f) => {
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file).push(f);
  });
  for (const [filePath, fs] of byFile) {
    md += `### \`${filePath}\`\n\n`;
    for (const f of fs) {
      md +=
        `- **[${f.severity.toUpperCase()}]** ${f.title} — ${f.cwe}` +
        (f.line ? ` _(line ${f.line})_` : '') +
        `\n`;
      md += `  _${f.remediation.replace(/\n+/g, ' ').slice(0, 220)}${f.remediation.length > 220 ? '…' : ''}_\n`;
    }
    md += '\n';
  }
  md += `</details>\n\n`;
  md += `<sub>Generated by Mid-Atlantic AI Pre-Flight Audit Tool · ${results.scannedAt.toISOString()}</sub>\n`;
  return md;
}

export function formatAgentPrompt(results) {
  const tier = riskTier(results.score);
  const top = results.findings.slice(0, 30);
  let p = `You are a senior application-security engineer. The findings below come from a static audit of a web app (score ${results.score}/100, ${tier.label}). For each finding, propose the smallest correct fix:\n`;
  p += `- If you have enough context, output a unified diff against the file.\n`;
  p += `- Otherwise describe the change in one or two sentences with a precise file:line reference.\n`;
  p += `- Group fixes by file when there are multiple in the same file.\n`;
  p += `- Call out any finding that needs human judgement (auth model, business logic) instead of guessing.\n\n`;
  p += `Findings (highest severity first):\n\n`;

  top.forEach((f, i) => {
    p += `### ${i + 1}. [${f.severity}] ${f.title}\n`;
    p += `- File: ${f.file}${f.line ? ':' + f.line : ''}\n`;
    p += `- Category: ${f.category} | ${f.cwe} | probe: ${f.probe}\n`;
    p += `- Evidence: ${f.evidence}\n`;
    if (f.snippet) {
      p += `- Code (line ${f.line} marked with \`>\`):\n`;
      p += '```\n' + snippetToText(f.snippet) + '\n```\n';
    }
    p += `- Remediation hint: ${f.remediation}\n\n`;
  });

  if (results.findings.length > top.length) {
    p += `(${results.findings.length - top.length} additional findings omitted to keep the prompt small. Re-export to a JSON file for full data.)\n`;
  }
  return p;
}
