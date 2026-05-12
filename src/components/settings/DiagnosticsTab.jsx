// src/components/settings/DiagnosticsTab.jsx
// The Settings home for the old "Diagnostics drawer" content. Default off — the live
// log buffer isn't useful to a typical user. When toggled on, renders the log viewer
// inline with the same severity filter / copy / download / clear actions the drawer
// version used to surface.
//
// Behavior parity with the old drawer:
//   - Same getLogs() ring-buffer source.
//   - Live updates via subscribe(); the log viewer re-renders on every emit.
//   - Same severity-filter dropdown (debug/info/warn/error).
//   - Same copy-to-clipboard + download + clear actions.

import { useEffect, useState } from 'react';
import { Copy, Download, Trash2 } from 'lucide-react';
import { T, fontMono } from '../../lib/theme.js';
import { getLogs, clearLogs, subscribe as subscribeLogs, exportLogs } from '../../lib/logger.js';
import { copyToClipboard, downloadFile, timestampSlug } from '../../lib/clipboard.js';

const COPY = `Pre-Flight keeps a rolling log of what it's doing in this tab. This panel is for debugging issues with the tool itself — most users will never need it. Toggle it on if something's behaving weird and you want to see what's happening, or if you're reporting a bug.`;

const LEVEL_RANK = { debug: 0, info: 1, warn: 2, error: 3 };

function DiagnosticsPanel() {
  const [tick, setTick] = useState(0);
  const [filter, setFilter] = useState('debug');
  useEffect(() => subscribeLogs(() => setTick((t) => t + 1)), []);
  void tick; // re-render trigger

  const all = getLogs();
  const visible = all.filter((e) => LEVEL_RANK[e.level] >= LEVEL_RANK[filter]);
  const counts = all.reduce((a, e) => ({ ...a, [e.level]: (a[e.level] || 0) + 1 }), {});

  const handleCopy = async () => {
    try {
      await copyToClipboard(exportLogs());
    } catch {
      // copyToClipboard already logs; nothing else to do
    }
  };
  const handleDownload = () => {
    downloadFile(
      exportLogs(),
      `pre-flight-logs-${timestampSlug(new Date())}.json`,
      'application/json'
    );
  };

  return (
    <div className="ap-card" style={{ padding: 18 }}>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 12,
          marginBottom: 14,
          flexWrap: 'wrap',
        }}
      >
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <label
            htmlFor="diag-level"
            className="ap-eyebrow"
            style={{ fontSize: 12, color: T.textMuted }}
          >
            LEVEL
          </label>
          <select
            id="diag-level"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="ap-input"
            style={{ padding: '4px 8px', fontSize: 13, width: 'auto', minHeight: 24 }}
          >
            <option value="debug">debug ({counts.debug || 0})</option>
            <option value="info">info ({counts.info || 0})</option>
            <option value="warn">warn ({counts.warn || 0})</option>
            <option value="error">error ({counts.error || 0})</option>
          </select>
          <span className="ap-mono" style={{ fontSize: 12, color: T.textMuted }}>
            {visible.length} / {all.length} entries
          </span>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <button
            onClick={handleCopy}
            className="ap-btn ap-btn-ghost"
            type="button"
            style={{ fontSize: 12, padding: '6px 10px' }}
            title="Copy all logs to clipboard"
          >
            <Copy
              size={11}
              aria-hidden="true"
              style={{ display: 'inline-block', marginRight: 4, verticalAlign: '-1px' }}
            />
            Copy
          </button>
          <button
            onClick={handleDownload}
            className="ap-btn ap-btn-ghost"
            type="button"
            style={{ fontSize: 12, padding: '6px 10px' }}
            title="Save logs as JSON"
          >
            <Download
              size={11}
              aria-hidden="true"
              style={{ display: 'inline-block', marginRight: 4, verticalAlign: '-1px' }}
            />
            Save
          </button>
          <button
            onClick={clearLogs}
            className="ap-btn ap-btn-ghost"
            type="button"
            style={{ fontSize: 12, padding: '6px 10px' }}
            title="Clear the log buffer"
          >
            <Trash2
              size={11}
              aria-hidden="true"
              style={{ display: 'inline-block', marginRight: 4, verticalAlign: '-1px' }}
            />
            Clear
          </button>
        </div>
      </div>

      <div
        role="log"
        aria-live="polite"
        style={{
          background: T.bg,
          border: `1px solid ${T.border}`,
          maxHeight: 480,
          overflowY: 'auto',
          fontFamily: fontMono,
          fontSize: 12,
          padding: 8,
        }}
      >
        {visible.length === 0 ? (
          <div style={{ color: T.textMuted, padding: 12, textAlign: 'center' }}>
            No log entries at this level.
          </div>
        ) : (
          visible.map((e) => (
            <div
              key={e.id}
              style={{
                padding: '4px 6px',
                marginBottom: 2,
                color:
                  e.level === 'error'
                    ? T.sev.critical.fg
                    : e.level === 'warn'
                      ? T.sev.medium.fg
                      : e.level === 'info'
                        ? T.text
                        : T.textMuted,
                borderBottom: `1px solid ${T.border}`,
              }}
            >
              <span style={{ color: T.textMuted }}>
                {new Date(e.ts).toISOString().slice(11, 23)}
              </span>{' '}
              <span style={{ textTransform: 'uppercase', fontWeight: 600 }}>[{e.level}]</span>{' '}
              <span style={{ color: T.textDim }}>[{e.scope}]</span> {e.message}
              {e.context && (
                <pre
                  style={{
                    margin: '4px 0 0 24px',
                    color: T.textDim,
                    fontSize: 11,
                    whiteSpace: 'pre-wrap',
                  }}
                >
                  {typeof e.context === 'string' ? e.context : JSON.stringify(e.context, null, 2)}
                </pre>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export function DiagnosticsTab() {
  const [show, setShow] = useState(false);
  return (
    <section>
      <h2 className="ap-display" style={{ margin: '0 0 14px', fontSize: 24, color: T.text }}>
        Diagnostics
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
        <p style={{ margin: 0, fontSize: 14, color: T.textDim, lineHeight: 1.7 }}>{COPY}</p>
      </div>

      <div className="ap-card" style={{ padding: 18, marginBottom: 14 }}>
        <label
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 10,
            cursor: 'pointer',
            minHeight: 24,
          }}
        >
          <input
            type="checkbox"
            checked={show}
            onChange={(e) => setShow(e.target.checked)}
            aria-label="Show diagnostics panel"
            style={{ width: 16, height: 16, cursor: 'pointer' }}
          />
          <span style={{ fontSize: 14, color: T.text }}>Show diagnostics panel</span>
        </label>
      </div>

      {show ? (
        <DiagnosticsPanel />
      ) : (
        <div
          className="ap-card"
          style={{ padding: 18, color: T.textMuted, fontSize: 14, fontStyle: 'italic' }}
        >
          Diagnostics hidden. Toggle on to view live logs.
        </div>
      )}
    </section>
  );
}
