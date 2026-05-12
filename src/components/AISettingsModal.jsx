// src/components/AISettingsModal.jsx
// BYOK provider/model/key form. Saves the user-pasted API key to localStorage and routes
// it only to the provider endpoint they chose — the audit-app origin never sees the key.
// The privacy contract is rendered in plain language inside the modal so the guarantee is
// visible BEFORE the user pastes a key.

import { useState, useEffect } from 'react';
import { X, Check, Trash2 } from 'lucide-react';
import { T } from '../lib/theme.js';
import { track } from '../lib/analytics.js';
import {
  AI_PROVIDERS,
  loadAIConfig,
  saveAIConfig,
  clearAIConfig,
  validateKeyShape,
} from '../lib/ai.js';

export function AISettingsModal({ open, onClose, onSaved }) {
  // We pull `existing` lazily into a state slot so we can refresh it (without `useMemo` having
  // a deps-array lint complaint) and so the form resets to the stored values each time the
  // modal re-opens. Updates are deferred via queueMicrotask so they don't fire synchronously
  // inside the effect tick (react-hooks/set-state-in-effect).
  const [existing, setExisting] = useState(() => loadAIConfig());
  const [provider, setProvider] = useState(existing?.provider || 'openai');
  const [apiKey, setApiKey] = useState(existing?.apiKey || '');
  const [model, setModel] = useState(existing?.model || AI_PROVIDERS.openai.defaultModel);
  const [reveal, setReveal] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!open) return;
    queueMicrotask(() => {
      const cfg = loadAIConfig();
      setExisting(cfg);
      setProvider(cfg?.provider || 'openai');
      setApiKey(cfg?.apiKey || '');
      setModel(cfg?.model || AI_PROVIDERS[cfg?.provider || 'openai'].defaultModel);
      setError(null);
    });
  }, [open]);

  if (!open) return null;
  const meta = AI_PROVIDERS[provider];
  const keyOk = !apiKey || validateKeyShape(provider, apiKey);

  const handleSave = () => {
    if (!apiKey.trim()) {
      setError('Paste an API key, or click Clear to remove the current one.');
      return;
    }
    if (!validateKeyShape(provider, apiKey)) {
      setError(
        `That doesn't look like a ${meta.label} key (expected pattern: ${meta.keyPlaceholder}).`
      );
      return;
    }
    try {
      saveAIConfig({ provider, apiKey, model });
      track(`ai.config.save.${provider}`);
      onSaved?.();
      onClose();
    } catch (e) {
      setError(e?.message || 'Could not save.');
    }
  };

  const handleClear = () => {
    clearAIConfig();
    setApiKey('');
    track('ai.config.clear');
    onSaved?.();
  };

  return (
    <>
      <div
        onClick={onClose}
        aria-hidden="true"
        style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 70 }}
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-label="AI provider settings"
        style={{
          position: 'fixed',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          maxWidth: 540,
          width: 'calc(100vw - 32px)',
          maxHeight: 'calc(100vh - 32px)',
          overflow: 'auto',
          background: T.panel,
          border: `1px solid ${T.borderAlt}`,
          padding: 24,
          zIndex: 80,
          boxShadow: '0 12px 40px rgba(0,0,0,0.6)',
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: 16,
          }}
        >
          <h2
            className="ap-display"
            style={{ margin: 0, fontSize: 22, fontWeight: 700, color: T.text }}
          >
            AI provider · BYOK
          </h2>
          <button
            onClick={onClose}
            aria-label="Close settings"
            type="button"
            style={{
              background: 'transparent',
              border: `1px solid ${T.border}`,
              color: T.textDim,
              cursor: 'pointer',
              padding: '6px 8px',
            }}
          >
            <X size={12} aria-hidden="true" />
          </button>
        </div>

        <p style={{ fontSize: 12, color: T.textDim, lineHeight: 1.7, marginBottom: 16 }}>
          The "Explain & Verify" button on each finding sends the finding metadata plus its ±5-line
          code snippet to the AI provider you choose, using <strong>your own key</strong>. Your key
          is stored in this browser's localStorage and is sent only to the provider's endpoint —
          never to our origin. There is no server proxy.
        </p>

        <div className="ap-eyebrow" style={{ marginBottom: 8 }}>
          PROVIDER
        </div>
        <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
          {Object.entries(AI_PROVIDERS).map(([key, p]) => (
            <button
              key={key}
              onClick={() => {
                setProvider(key);
                setModel(p.defaultModel);
                setError(null);
              }}
              className="ap-mono"
              style={{
                flex: 1,
                padding: '10px 12px',
                fontSize: 12,
                background: provider === key ? T.accent : 'transparent',
                color: provider === key ? T.bg : T.textDim,
                border: `1px solid ${provider === key ? T.accent : T.border}`,
                cursor: 'pointer',
                fontWeight: 600,
              }}
            >
              {p.label}
            </button>
          ))}
        </div>

        <label
          htmlFor="ai-key-input"
          className="ap-eyebrow"
          style={{ display: 'block', marginBottom: 8 }}
        >
          API KEY
        </label>
        <div style={{ position: 'relative', marginBottom: 4 }}>
          <input
            id="ai-key-input"
            className="ap-input"
            type={reveal ? 'text' : 'password'}
            placeholder={meta.keyPlaceholder}
            value={apiKey}
            onChange={(e) => {
              setApiKey(e.target.value);
              setError(null);
            }}
            autoComplete="off"
            spellCheck={false}
            style={{ paddingRight: 70 }}
          />
          <button
            type="button"
            onClick={() => setReveal((v) => !v)}
            className="ap-mono"
            style={{
              position: 'absolute',
              right: 8,
              top: '50%',
              transform: 'translateY(-50%)',
              background: 'transparent',
              border: `1px solid ${T.border}`,
              color: T.textDim,
              cursor: 'pointer',
              fontSize: 10,
              padding: '4px 10px',
            }}
          >
            {reveal ? 'hide' : 'show'}
          </button>
        </div>
        <p style={{ fontSize: 11, color: T.textMuted, marginBottom: 16 }}>
          Get a key from{' '}
          <a
            href={meta.docsUrl}
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: T.accent }}
          >
            {meta.docsUrl}
          </a>
          .{' '}
          {apiKey && !keyOk && (
            <span style={{ color: T.sev.medium.fg }}> Key shape doesn't match {meta.label}.</span>
          )}
        </p>

        <label
          htmlFor="ai-model-input"
          className="ap-eyebrow"
          style={{ display: 'block', marginBottom: 8 }}
        >
          MODEL
        </label>
        <select
          id="ai-model-input"
          value={model}
          onChange={(e) => setModel(e.target.value)}
          className="ap-input"
          style={{ marginBottom: 16 }}
        >
          {meta.models.map((m) => (
            <option key={m} value={m}>
              {m}
              {m === meta.defaultModel ? ' (default)' : ''}
            </option>
          ))}
        </select>

        {error && (
          <div
            role="alert"
            style={{
              padding: 10,
              marginBottom: 16,
              fontSize: 12,
              background: T.sev.critical.bg,
              border: `1px solid ${T.sev.critical.border}`,
              color: T.sev.critical.fg,
            }}
          >
            {error}
          </div>
        )}

        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          {existing && (
            <button onClick={handleClear} className="ap-btn ap-btn-ghost" type="button">
              <Trash2
                size={12}
                aria-hidden="true"
                style={{ display: 'inline-block', marginRight: 6, verticalAlign: '-1px' }}
              />
              Clear stored key
            </button>
          )}
          <button onClick={onClose} className="ap-btn ap-btn-ghost" type="button">
            Cancel
          </button>
          <button onClick={handleSave} className="ap-btn" type="button">
            <Check
              size={12}
              aria-hidden="true"
              style={{ display: 'inline-block', marginRight: 6, verticalAlign: '-1px' }}
            />
            Save
          </button>
        </div>
      </div>
    </>
  );
}
