import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  AI_PROVIDERS,
  loadAIConfig,
  saveAIConfig,
  clearAIConfig,
  hasAIConfig,
  validateKeyShape,
  buildExplainVerifyMessages,
  callAI,
  explainAndVerify,
} from '../lib/ai.js';

const sampleFinding = () => ({
  id: 'x',
  probe: 'Secret Scanner',
  title: 'AWS Access Key found in source',
  severity: 'critical',
  category: 'Data Breach',
  cwe: 'CWE-798',
  file: 'src/config.js',
  line: 7,
  evidence: 'const k = "AKIA...XXXX"',
  remediation: 'Rotate the key.',
  snippet: {
    startLine: 5,
    endLine: 9,
    lines: [
      { n: 5, text: '// init', isHit: false },
      { n: 6, text: 'export const cfg = {', isHit: false },
      { n: 7, text: '  awsKey: "AKIA...XXXX",', isHit: true },
      { n: 8, text: '};', isHit: false },
      { n: 9, text: '', isHit: false },
    ],
  },
});

describe('BYOK config storage', () => {
  beforeEach(() => {
    if (typeof localStorage !== 'undefined') localStorage.clear();
  });

  it('returns null when no config is stored', () => {
    expect(loadAIConfig()).toBeNull();
    expect(hasAIConfig()).toBe(false);
  });

  it('saves and loads a valid config', () => {
    saveAIConfig({ provider: 'openai', apiKey: 'sk-' + 'a'.repeat(40) });
    const cfg = loadAIConfig();
    expect(cfg.provider).toBe('openai');
    expect(cfg.apiKey).toMatch(/^sk-/);
    expect(cfg.model).toBe(AI_PROVIDERS.openai.defaultModel);
    expect(hasAIConfig()).toBe(true);
  });

  it('rejects unknown provider', () => {
    expect(() => saveAIConfig({ provider: 'bogus', apiKey: 'x' })).toThrow();
  });

  it('rejects empty key', () => {
    expect(() => saveAIConfig({ provider: 'openai', apiKey: '' })).toThrow();
    expect(() => saveAIConfig({ provider: 'openai', apiKey: '   ' })).toThrow();
  });

  it('clearAIConfig removes the stored key', () => {
    saveAIConfig({ provider: 'anthropic', apiKey: 'sk-ant-' + 'a'.repeat(40) });
    expect(hasAIConfig()).toBe(true);
    clearAIConfig();
    expect(hasAIConfig()).toBe(false);
  });

  it('ignores malformed JSON in localStorage', () => {
    localStorage.setItem('audit-app:ai-config:v1', '{ not valid');
    expect(loadAIConfig()).toBeNull();
  });
});

describe('validateKeyShape', () => {
  it('accepts plausibly-shaped OpenAI keys', () => {
    expect(validateKeyShape('openai', 'sk-' + 'a'.repeat(40))).toBe(true);
  });
  it('accepts plausibly-shaped Anthropic keys', () => {
    expect(validateKeyShape('anthropic', 'sk-ant-' + 'a'.repeat(40))).toBe(true);
  });
  it('rejects wrong-prefix keys', () => {
    expect(validateKeyShape('openai', 'sk-ant-' + 'a'.repeat(40))).toBe(false);
    expect(validateKeyShape('anthropic', 'sk-' + 'a'.repeat(40))).toBe(false);
  });
  it('rejects empty and unknown providers', () => {
    expect(validateKeyShape('openai', '')).toBe(false);
    expect(validateKeyShape('bogus', 'sk-...')).toBe(false);
  });
});

describe('buildExplainVerifyMessages', () => {
  it('embeds the finding metadata and snippet', () => {
    const { system, user } = buildExplainVerifyMessages(sampleFinding());
    expect(system).toMatch(/two parts ONLY/);
    expect(system).toMatch(/LIKELY TRUE POSITIVE|LIKELY FALSE POSITIVE|INSUFFICIENT CONTEXT/);
    expect(user).toMatch(/AWS Access Key found in source/);
    expect(user).toMatch(/src\/config\.js:7/);
    expect(user).toMatch(/awsKey: "AKIA\.\.\.XXXX"/);
    expect(user).toMatch(/CWE-798/);
  });

  it('handles findings without a snippet gracefully', () => {
    const f = sampleFinding();
    f.snippet = null;
    const { user } = buildExplainVerifyMessages(f);
    expect(user).toMatch(/no code snippet attached/);
  });

  it('never asks the model to propose fixes (privacy / scope guard)', () => {
    const { system } = buildExplainVerifyMessages(sampleFinding());
    expect(system).toMatch(/Do not propose fixes/i);
    expect(system).toMatch(/Do not request more code/i);
  });
});

describe('callAI streaming (mocked fetch)', () => {
  it('streams OpenAI SSE chunks correctly', async () => {
    const fakeBody = [
      'data: {"choices":[{"delta":{"content":"Hello "}}]}',
      'data: {"choices":[{"delta":{"content":"world"}}]}',
      'data: [DONE]',
      '',
    ].join('\n');

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(fakeBody));
          controller.close();
        },
      }),
    });

    const chunks = [];
    const out = await callAI(
      { provider: 'openai', apiKey: 'sk-' + 'a'.repeat(40), model: 'gpt-4o-mini' },
      buildExplainVerifyMessages(sampleFinding()),
      (chunk) => chunks.push(chunk)
    );
    expect(chunks).toEqual(['Hello ', 'world']);
    expect(out).toBe('Hello world');
  });

  it('streams Anthropic SSE chunks correctly', async () => {
    const fakeBody = [
      'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hello "}}',
      'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"world"}}',
      'data: {"type":"message_stop"}',
      'data: [DONE]',
      '',
    ].join('\n');

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(fakeBody));
          controller.close();
        },
      }),
    });

    const chunks = [];
    const out = await callAI(
      { provider: 'anthropic', apiKey: 'sk-ant-' + 'a'.repeat(40), model: 'claude-haiku-4-5' },
      buildExplainVerifyMessages(sampleFinding()),
      (chunk) => chunks.push(chunk)
    );
    expect(chunks).toEqual(['Hello ', 'world']);
    expect(out).toBe('Hello world');
  });

  it('throws on non-200 response with the provider error body included', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      text: async () => '{"error":"invalid_api_key"}',
    });
    await expect(
      callAI(
        { provider: 'openai', apiKey: 'sk-bad', model: 'gpt-4o-mini' },
        { system: 's', user: 'u' },
        () => {}
      )
    ).rejects.toThrow(/OpenAI API 401/);
  });
});

describe('explainAndVerify', () => {
  beforeEach(() => {
    if (typeof localStorage !== 'undefined') localStorage.clear();
  });

  it('throws when no config is stored', async () => {
    await expect(explainAndVerify(sampleFinding(), () => {})).rejects.toThrow(
      /No AI provider configured/
    );
  });

  it('uses stored config to dispatch the call', async () => {
    saveAIConfig({ provider: 'openai', apiKey: 'sk-' + 'a'.repeat(40) });
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(
            new TextEncoder().encode(
              'data: {"choices":[{"delta":{"content":"ok"}}]}\ndata: [DONE]\n'
            )
          );
          controller.close();
        },
      }),
    });
    const out = await explainAndVerify(sampleFinding(), () => {});
    expect(out).toBe('ok');
    expect(global.fetch).toHaveBeenCalled();
    const [url, opts] = global.fetch.mock.calls[0];
    expect(url).toBe('https://api.openai.com/v1/chat/completions');
    // Privacy invariant: only the finding-scoped payload is sent.
    const body = JSON.parse(opts.body);
    expect(body.messages[1].content).toMatch(/AWS Access Key/);
    expect(body.messages[1].content).not.toMatch(/audit-app/);
  });
});
