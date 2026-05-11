// src/lib/ai.js
// Bring-Your-Own-Key (BYOK) AI integration for the "Explain & Verify" per-finding action.
//
// Privacy contract:
// - The user's API key is read from localStorage and sent ONLY to the provider's endpoint.
// - The audit-app origin never sees the key. There is no proxy. There is no server in the loop.
// - No telemetry / analytics call records the key or the response body.
// - Per-finding responses are cached in-memory for the session (not persisted) so re-clicking
//   doesn't re-spend tokens.
//
// Supported providers:
// - openai:  https://api.openai.com/v1/chat/completions
// - anthropic: https://api.anthropic.com/v1/messages
//
// The user picks a provider, model, and key. Both providers support CORS for direct browser calls
// (Anthropic since 2024 with the `anthropic-dangerous-direct-browser-access` header).

const STORAGE_KEY = 'audit-app:ai-config:v1';

export const AI_PROVIDERS = {
  openai: {
    label: 'OpenAI',
    endpoint: 'https://api.openai.com/v1/chat/completions',
    models: ['gpt-4o-mini', 'gpt-4o', 'gpt-4.1', 'gpt-4.1-mini', 'gpt-5'],
    defaultModel: 'gpt-4o-mini',
    docsUrl: 'https://platform.openai.com/api-keys',
    keyPlaceholder: 'sk-...',
    // Negative lookahead so sk-ant- (Anthropic) doesn't pass the OpenAI test.
    keyPattern: /^sk-(?!ant-)[A-Za-z0-9_\-]{20,}$/,
  },
  anthropic: {
    label: 'Anthropic (Claude)',
    endpoint: 'https://api.anthropic.com/v1/messages',
    models: ['claude-haiku-4-5', 'claude-sonnet-4-6', 'claude-opus-4-7'],
    defaultModel: 'claude-haiku-4-5',
    docsUrl: 'https://console.anthropic.com/settings/keys',
    keyPlaceholder: 'sk-ant-...',
    keyPattern: /^sk-ant-[A-Za-z0-9_\-]{20,}$/,
  },
};

export function loadAIConfig() {
  try {
    if (typeof localStorage === 'undefined') return null;
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || !parsed.provider || !parsed.apiKey) return null;
    if (!AI_PROVIDERS[parsed.provider]) return null;
    return {
      provider: parsed.provider,
      apiKey: parsed.apiKey,
      model: parsed.model || AI_PROVIDERS[parsed.provider].defaultModel,
    };
  } catch {
    return null;
  }
}

export function saveAIConfig({ provider, apiKey, model }) {
  if (!AI_PROVIDERS[provider]) throw new Error(`Unknown AI provider: ${provider}`);
  if (typeof apiKey !== 'string' || !apiKey.trim()) throw new Error('API key is empty.');
  const cfg = {
    provider,
    apiKey: apiKey.trim(),
    model: model || AI_PROVIDERS[provider].defaultModel,
  };
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(cfg));
  } catch {
    throw new Error('Could not save AI config (localStorage may be disabled).');
  }
  return cfg;
}

export function clearAIConfig() {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {}
}

export function hasAIConfig() {
  return loadAIConfig() !== null;
}

// Quick smoke-test: was the key shaped right?
export function validateKeyShape(provider, key) {
  const p = AI_PROVIDERS[provider];
  if (!p) return false;
  return p.keyPattern.test((key || '').trim());
}

// Build the prompt sent for Explain & Verify.
// Constraints:
// - Send ONLY the finding metadata + ±5-line code snippet. Never the rest of the codebase.
// - Two outputs requested: (1) plain-English explanation, (2) TP/FP verdict.
// - Ask for short, structured output to keep token cost low and rendering simple.
export function buildExplainVerifyMessages(finding) {
  const snippetText = finding.snippet?.lines
    ? finding.snippet.lines
        .map((l) => `${String(l.n).padStart(4)}${l.isHit ? '> ' : ': '}${l.text}`)
        .join('\n')
    : '(no code snippet attached)';

  const system =
    `You are a senior application-security reviewer triaging a finding from a static security scanner. ` +
    `You will be given the finding details + a small code snippet (±5 lines around the offending line). ` +
    `Respond in two parts ONLY:\n\n` +
    `(1) **Explain** — 2–4 sentences explaining what the finding means, why it matters, and what a beginner needs to know to make sense of it. Plain English, no jargon without unpacking it.\n\n` +
    `(2) **Verify** — Output exactly one of: "LIKELY TRUE POSITIVE", "LIKELY FALSE POSITIVE", or "INSUFFICIENT CONTEXT". Then 1–2 sentences justifying that verdict based on the snippet alone. If the snippet doesn't show enough context to decide, say so — do not invent context.\n\n` +
    `Do not propose fixes — the scanner already provides remediation text. Do not request more code. Keep the entire response under 200 words.`;

  const user =
    `Finding from PreFlight static scanner:\n\n` +
    `- Probe: ${finding.probe}\n` +
    `- Title: ${finding.title}\n` +
    `- Severity: ${finding.severity}\n` +
    `- Category: ${finding.category}\n` +
    `- CWE: ${finding.cwe}\n` +
    `- File: ${finding.file}${finding.line ? ':' + finding.line : ''}\n\n` +
    `Code snippet (hit line marked with \`>\`):\n\`\`\`\n${snippetText}\n\`\`\`\n\n` +
    `Evidence captured by the scanner: ${finding.evidence}`;

  return { system, user };
}

// Provider-specific calls. Both return a stream of incremental text chunks via the onChunk callback.
// Returns a Promise that resolves to the full text on success, throws on error.
export async function callAI({ provider, apiKey, model }, messages, onChunk, signal) {
  if (!AI_PROVIDERS[provider]) throw new Error(`Unknown AI provider: ${provider}`);
  if (provider === 'openai') return callOpenAI({ apiKey, model }, messages, onChunk, signal);
  if (provider === 'anthropic') return callAnthropic({ apiKey, model }, messages, onChunk, signal);
  throw new Error(`Provider ${provider} not implemented`);
}

async function callOpenAI({ apiKey, model }, { system, user }, onChunk, signal) {
  const resp = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model,
      stream: true,
      max_tokens: 600,
      temperature: 0.2,
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: user },
      ],
    }),
    signal,
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    throw new Error(`OpenAI API ${resp.status}: ${text.slice(0, 300)}`);
  }
  return readSSE(resp, onChunk, (data) => {
    try {
      const obj = JSON.parse(data);
      return obj?.choices?.[0]?.delta?.content || '';
    } catch {
      return '';
    }
  });
}

async function callAnthropic({ apiKey, model }, { system, user }, onChunk, signal) {
  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
      'anthropic-dangerous-direct-browser-access': 'true',
    },
    body: JSON.stringify({
      model,
      max_tokens: 600,
      temperature: 0.2,
      system,
      stream: true,
      messages: [{ role: 'user', content: user }],
    }),
    signal,
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    throw new Error(`Anthropic API ${resp.status}: ${text.slice(0, 300)}`);
  }
  return readSSE(resp, onChunk, (data) => {
    try {
      const obj = JSON.parse(data);
      // Anthropic streams content_block_delta events.
      if (obj.type === 'content_block_delta' && obj.delta?.type === 'text_delta') {
        return obj.delta.text || '';
      }
    } catch {}
    return '';
  });
}

// Generic SSE reader: parses `data: ...` lines, calls extractText per data block,
// invokes onChunk with each incremental chunk, and accumulates the total.
async function readSSE(resp, onChunk, extractText) {
  if (!resp.body) throw new Error('Streaming response had no body');
  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  let total = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      const trimmed = line.trim();
      if (!trimmed.startsWith('data:')) continue;
      const data = trimmed.slice(5).trim();
      if (data === '[DONE]') return total;
      const chunk = extractText(data);
      if (chunk) {
        total += chunk;
        try {
          onChunk?.(chunk, total);
        } catch {}
      }
    }
  }
  return total;
}

// Convenience wrapper: run Explain & Verify on a finding, with a callback for streamed text.
// Returns a Promise resolving to the full text. Throws on network/auth/quota error.
export async function explainAndVerify(finding, onChunk, signal) {
  const cfg = loadAIConfig();
  if (!cfg) throw new Error('No AI provider configured. Open Settings to add a key.');
  const messages = buildExplainVerifyMessages(finding);
  return callAI(cfg, messages, onChunk, signal);
}
