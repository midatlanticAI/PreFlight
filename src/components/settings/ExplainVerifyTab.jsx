// src/components/settings/ExplainVerifyTab.jsx
// BYOK form, lifted from the old AISettingsModal. Wires to src/lib/ai.js — provider,
// model, key all stored in localStorage. No server proxy; the key is sent only to the
// provider endpoint the user chose.
//
// Three pieces of UX the old modal didn't have, that the v0.4 spec asks for:
//   - "Test connection" button that hits the provider with a trivial request and
//     surfaces the success/failure inline.
//   - Outbound links to both provider key-management pages.
//   - Reset-to-"None" semantics so the user can opt out without deleting the key
//     manually each time.

import { useState, useEffect } from 'react';
import { Check, Eye, EyeOff, Trash2, ExternalLink, Wifi } from 'lucide-react';
import { T, fontMono } from '../../lib/theme.js';
import { track } from '../../lib/analytics.js';
import {
  AI_PROVIDERS,
  loadAIConfig,
  saveAIConfig,
  clearAIConfig,
  validateKeyShape,
} from '../../lib/ai.js';

const COPY = `Pre-Flight can ask an AI model to look at a specific finding and tell you whether it's a real issue or a false positive. This is opt-in and uses your own API key (called BYOK — Bring Your Own Key), which means three things: (1) your key never touches our server because there is no server, (2) you control your own usage and billing directly with the provider, (3) you can revoke access by deleting the key from this panel, no account to cancel.

What gets sent to the AI: the finding details (probe, file path, severity), about ten lines of code context, and a request to verify. Your full source code is never sent. The provider you choose has its own data retention policy — review it before pasting your key.`;

const KEY_LINKS = {
  anthropic: { label: 'Get an Anthropic API key', url: 'https://console.anthropic.com/' },
  openai: { label: 'Get an OpenAI API key', url: 'https://platform.openai.com/' },
};

export function ExplainVerifyTab() {
  const [provider, setProvider] = useState('none'); // 'none' | 'anthropic' | 'openai'
  const [apiKey, setApiKey] = useState('');
  const [model, setModel] = useState('');
  const [reveal, setReveal] = useState(false);
  const [status, setStatus] = useState(null); // { kind: 'ok'|'err'|'info', text: string }
  const [testing, setTesting] = useState(false);

  // Hydrate from store on mount. queueMicrotask defers the state-set out of render.
  useEffect(() => {
    queueMicrotask(() => {
      const cfg = loadAIConfig();
      if (cfg && AI_PROVIDERS[cfg.provider]) {
        setProvider(cfg.provider);
        setApiKey(cfg.apiKey || '');
        setModel(cfg.model || AI_PROVIDERS[cfg.provider].defaultModel);
      }
    });
  }, []);

  const handleProviderChange = (p) => {
    setProvider(p);
    setStatus(null);
    if (p === 'none') {
      setApiKey('');
      setModel('');
    } else {
      setModel(AI_PROVIDERS[p].defaultModel);
    }
  };

  const handleSave = () => {
    if (provider === 'none') {
      clearAIConfig();
      track('ai.config.clear');
      window.dispatchEvent(new Event('preflight:ai-config-changed'));
      setStatus({ kind: 'ok', text: 'AI disabled. Stored key removed.' });
      return;
    }
    if (!apiKey.trim()) {
      setStatus({ kind: 'err', text: 'Paste an API key or switch the provider to None.' });
      return;
    }
    if (!validateKeyShape(provider, apiKey)) {
      setStatus({
        kind: 'err',
        text: `That doesn't look like a ${AI_PROVIDERS[provider].label} key (expected pattern: ${AI_PROVIDERS[provider].keyPlaceholder}).`,
      });
      return;
    }
    try {
      saveAIConfig({ provider, apiKey, model });
      track(`ai.config.save.${provider}`);
      // Tell App.jsx the config changed so the in-memory aiConfig refreshes without a reload.
      window.dispatchEvent(new Event('preflight:ai-config-changed'));
      setStatus({ kind: 'ok', text: 'Saved. Explain & Verify is now available on each finding.' });
    } catch (e) {
      setStatus({ kind: 'err', text: e?.message || 'Could not save.' });
    }
  };

  const handleClear = () => {
    clearAIConfig();
    setApiKey('');
    setProvider('none');
    setModel('');
    window.dispatchEvent(new Event('preflight:ai-config-changed'));
    setStatus({ kind: 'ok', text: 'Stored key removed.' });
    track('ai.config.clear');
  };

  // Lightweight connectivity probe. Calls the provider endpoint with a minimum-tokens
  // request. We don't stream — just need a non-error response to confirm the key works.
  const handleTest = async () => {
    if (provider === 'none' || !apiKey.trim()) {
      setStatus({ kind: 'err', text: 'Pick a provider and paste a key first.' });
      return;
    }
    setTesting(true);
    setStatus({ kind: 'info', text: 'Testing connection…' });
    try {
      const url =
        provider === 'anthropic'
          ? 'https://api.anthropic.com/v1/messages'
          : 'https://api.openai.com/v1/chat/completions';
      const headers =
        provider === 'anthropic'
          ? {
              'content-type': 'application/json',
              'x-api-key': apiKey.trim(),
              'anthropic-version': '2023-06-01',
              'anthropic-dangerous-direct-browser-access': 'true',
            }
          : {
              'content-type': 'application/json',
              authorization: `Bearer ${apiKey.trim()}`,
            };
      const body =
        provider === 'anthropic'
          ? JSON.stringify({
              model: model || AI_PROVIDERS.anthropic.defaultModel,
              max_tokens: 1,
              messages: [{ role: 'user', content: 'ping' }],
            })
          : JSON.stringify({
              model: model || AI_PROVIDERS.openai.defaultModel,
              max_tokens: 1,
              messages: [{ role: 'user', content: 'ping' }],
            });
      const resp = await fetch(url, { method: 'POST', headers, body });
      if (resp.ok) {
        setStatus({ kind: 'ok', text: 'Connection OK. Key is valid for this provider.' });
      } else {
        const text = await resp.text().catch(() => '');
        setStatus({
          kind: 'err',
          text: `${resp.status} ${resp.statusText} — ${text.slice(0, 200)}`,
        });
      }
    } catch (e) {
      setStatus({ kind: 'err', text: e?.message || 'Network call failed.' });
    } finally {
      setTesting(false);
    }
  };

  const placeholder =
    provider === 'none' ? '' : AI_PROVIDERS[provider]?.keyPlaceholder || 'paste key here';

  return (
    <section>
      <h2 className="ap-display" style={{ margin: '0 0 14px', fontSize: 22, color: T.text }}>
        Explain &amp; Verify
      </h2>

      <div
        className="ap-card"
        style={{
          padding: 18,
          marginBottom: 18,
          background: T.bg,
          borderLeft: `3px solid ${T.accentAlt}`,
        }}
      >
        <div className="ap-eyebrow" style={{ marginBottom: 6, color: T.accentAlt }}>
          BYOK — BRING YOUR OWN KEY
        </div>
        <p
          style={{
            margin: 0,
            fontSize: 13,
            color: T.textDim,
            lineHeight: 1.7,
            whiteSpace: 'pre-line',
          }}
        >
          {COPY}
        </p>
      </div>

      <div className="ap-card" style={{ padding: 18, marginBottom: 14 }}>
        <h3 className="ap-eyebrow" style={{ margin: '0 0 10px', fontSize: 11, color: T.textMuted }}>
          PROVIDER
        </h3>
        <div style={{ display: 'flex', gap: 8, marginBottom: 18, flexWrap: 'wrap' }}>
          {['anthropic', 'openai', 'none'].map((p) => (
            <label
              key={p}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                padding: '8px 14px',
                border: `1px solid ${provider === p ? T.accent : T.border}`,
                background: provider === p ? T.accent : 'transparent',
                color: provider === p ? T.bg : T.textDim,
                cursor: 'pointer',
                fontFamily: fontMono,
                fontSize: 12,
                fontWeight: 600,
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                minHeight: 24,
              }}
            >
              <input
                type="radio"
                name="ai-provider"
                value={p}
                checked={provider === p}
                onChange={() => handleProviderChange(p)}
                style={{ display: 'none' }}
              />
              {p === 'none' ? 'None (off)' : AI_PROVIDERS[p].label}
            </label>
          ))}
        </div>

        {provider !== 'none' && (
          <>
            <label
              htmlFor="ai-key"
              className="ap-eyebrow"
              style={{ display: 'block', marginBottom: 8, fontSize: 11, color: T.textMuted }}
            >
              API KEY
            </label>
            <div style={{ position: 'relative', marginBottom: 12 }}>
              <input
                id="ai-key"
                type={reveal ? 'text' : 'password'}
                className="ap-input"
                placeholder={placeholder}
                value={apiKey}
                onChange={(e) => {
                  setApiKey(e.target.value);
                  setStatus(null);
                }}
                autoComplete="off"
                spellCheck={false}
                style={{ paddingRight: 70 }}
              />
              <button
                type="button"
                onClick={() => setReveal((v) => !v)}
                aria-label={reveal ? 'Hide key' : 'Show key'}
                className="ap-mono"
                style={{
                  position: 'absolute',
                  right: 6,
                  top: '50%',
                  transform: 'translateY(-50%)',
                  background: 'transparent',
                  border: `1px solid ${T.border}`,
                  color: T.textDim,
                  cursor: 'pointer',
                  fontSize: 10,
                  padding: '4px 8px',
                  minHeight: 24,
                }}
              >
                {reveal ? (
                  <EyeOff size={11} aria-hidden="true" />
                ) : (
                  <Eye size={11} aria-hidden="true" />
                )}
                <span style={{ marginLeft: 4 }}>{reveal ? 'hide' : 'show'}</span>
              </button>
            </div>

            <label
              htmlFor="ai-model"
              className="ap-eyebrow"
              style={{ display: 'block', marginBottom: 8, fontSize: 11, color: T.textMuted }}
            >
              MODEL
            </label>
            <select
              id="ai-model"
              className="ap-input"
              value={model}
              onChange={(e) => setModel(e.target.value)}
              style={{ marginBottom: 14 }}
            >
              {AI_PROVIDERS[provider]?.models?.map((m) => (
                <option key={m} value={m}>
                  {m}
                  {m === AI_PROVIDERS[provider].defaultModel ? ' (default)' : ''}
                </option>
              ))}
            </select>

            <a
              href={KEY_LINKS[provider].url}
              target="_blank"
              rel="noopener noreferrer"
              className="ap-mono"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 4,
                color: T.accent,
                fontSize: 12,
                marginBottom: 14,
              }}
            >
              {KEY_LINKS[provider].label}
              <ExternalLink size={10} aria-hidden="true" />
            </a>
          </>
        )}

        {status && (
          <div
            role="status"
            aria-live="polite"
            style={{
              padding: 10,
              marginBottom: 12,
              fontSize: 12,
              background:
                status.kind === 'ok'
                  ? T.sev.info.bg
                  : status.kind === 'err'
                    ? T.sev.critical.bg
                    : T.panelAlt,
              border: `1px solid ${
                status.kind === 'ok'
                  ? T.sev.info.border
                  : status.kind === 'err'
                    ? T.sev.critical.border
                    : T.border
              }`,
              color:
                status.kind === 'ok'
                  ? T.good
                  : status.kind === 'err'
                    ? T.sev.critical.fg
                    : T.textDim,
            }}
          >
            {status.text}
          </div>
        )}

        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button
            onClick={handleSave}
            className="ap-btn"
            type="button"
            style={{ fontSize: 12 }}
            disabled={testing}
          >
            <Check
              size={12}
              aria-hidden="true"
              style={{ display: 'inline-block', marginRight: 6, verticalAlign: '-1px' }}
            />
            {provider === 'none' ? 'Confirm off' : 'Save'}
          </button>
          {provider !== 'none' && (
            <button
              onClick={handleTest}
              className="ap-btn ap-btn-ghost"
              type="button"
              style={{ fontSize: 12 }}
              disabled={testing}
            >
              <Wifi
                size={12}
                aria-hidden="true"
                style={{ display: 'inline-block', marginRight: 6, verticalAlign: '-1px' }}
              />
              {testing ? 'Testing…' : 'Test connection'}
            </button>
          )}
          <button
            onClick={handleClear}
            className="ap-btn ap-btn-ghost"
            type="button"
            style={{ fontSize: 12 }}
            disabled={testing}
          >
            <Trash2
              size={12}
              aria-hidden="true"
              style={{ display: 'inline-block', marginRight: 6, verticalAlign: '-1px' }}
            />
            Clear key
          </button>
        </div>
      </div>
    </section>
  );
}
