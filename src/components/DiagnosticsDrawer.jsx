// src/components/DiagnosticsDrawer.jsx
// Bottom-sheet drawer that surfaces the live log buffer with severity filtering,
// keyboard focus trap, and copy / download / clear actions. The drawer toggles via
// the floating bug button at the bottom-right of the App layout.
//
// State source: the ring-buffer logger in src/lib/logger.js. Reads via getLogs() and
// subscribes to live updates via subscribe(). Severity  is owned by the
// parent App so it survives drawer-close.

import { useEffect, useRef } from 'react';
import { Activity, Copy, Download, Trash2, X } from 'lucide-react';
import { T, fontMono } from '../lib/theme.js';
import { log, getLogs, clearLogs, exportLogs } from '../lib/logger.js';
import { copyToClipboard, downloadFile, timestampSlug } from '../lib/clipboard.js';

export function DiagnosticsDrawer({ open, onClose, filter, setFilter }) {
  const all = getLogs();
  const RANK = { debug: 0, info: 1, warn: 2, error: 3 };
  const visible = all.filter((e) => RANK[e.level] >= RANK[filter]);
  const counts = all.reduce((a, e) => {
    a[e.level] = (a[e.level] || 0) + 1;
    return a;
  }, {});
  const handleCopy = async () => {
    try {
      await copyToClipboard(exportLogs());
    } catch (e) {
      log.warn('diagnostics: copy logs failed', { error: e?.message });
    }
  };
  const handleDownload = () => {
    downloadFile(exportLogs(), `audit-logs-${timestampSlug(new Date())}.json`, 'application/json');
  };
  const drawerRef = useRef(null);
  const closeBtnRef = useRef(null);
  const lastFocusRef = useRef(null);

  // Focus management: trap Tab inside drawer, focus close button on open, restore focus on close.
  useEffect(() => {
    if (!open) return;
    lastFocusRef.current = document.activeElement;
    // Defer to next tick so the close button is in the DOM and focusable.
    const t = setTimeout(() => closeBtnRef.current?.focus(), 0);
    const onKey = (e) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key !== 'Tab') return;
      const focusable = drawerRef.current?.querySelectorAll(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      );
      if (!focusable || focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => {
      clearTimeout(t);
      document.removeEventListener('keydown', onKey);
      // Restore focus to whatever element opened the drawer.
      if (lastFocusRef.current && lastFocusRef.current.focus) {
        try {
          lastFocusRef.current.focus();
        } catch (e) {
          log.debug('drawer: focus restore failed', { error: e?.message });
        }
      }
    };
  }, [open, onClose]);

  return (
    <>
      {open && (
        <div
          onClick={onClose}
          aria-hidden="true"
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.4)',
            zIndex: 50,
          }}
        />
      )}
      <div
        ref={drawerRef}
        role="dialog"
        aria-label="Diagnostics log"
        aria-modal="true"
        aria-hidden={!open}
        style={{
          position: 'fixed',
          left: 0,
          right: 0,
          bottom: 0,
          maxHeight: '60vh',
          background: T.panel,
          borderTop: `2px solid ${T.accent}`,
          transform: open ? 'translateY(0)' : 'translateY(100%)',
          transition: 'transform 0.25s ease-out',
          zIndex: 60,
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        <div
          style={{
            padding: '12px 18px',
            borderBottom: `1px solid ${T.border}`,
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            flexWrap: 'wrap',
          }}
        >
          <Activity size={14} color={T.accent} />
          <span className="ap-eyebrow" style={{ color: T.text }}>
            DIAGNOSTICS · {visible.length} / {all.length}
          </span>
          <div style={{ display: 'flex', gap: 4 }}>
            {['debug', 'info', 'warn', 'error'].map((lvl) => (
              <button
                key={lvl}
                onClick={() => setFilter(lvl)}
                className="ap-mono"
                style={{
                  fontSize: 10,
                  padding: '4px 8px',
                  letterSpacing: '0.1em',
                  textTransform: 'uppercase',
                  background: filter === lvl ? T.accent : 'transparent',
                  color: filter === lvl ? T.bg : T.textDim,
                  border: `1px solid ${filter === lvl ? T.accent : T.border}`,
                  cursor: 'pointer',
                }}
              >
                {lvl} {counts[lvl] ? `(${counts[lvl]})` : ''}
              </button>
            ))}
          </div>
          <div style={{ flex: 1 }} />
          <button
            onClick={handleCopy}
            className="ap-btn ap-btn-ghost"
            style={{ padding: '6px 12px', fontSize: 10 }}
            title="Copy all logs as JSON"
          >
            <Copy
              size={11}
              style={{ display: 'inline-block', marginRight: 5, verticalAlign: '-1px' }}
            />
            Copy
          </button>
          <button
            onClick={handleDownload}
            className="ap-btn ap-btn-ghost"
            style={{ padding: '6px 12px', fontSize: 10 }}
            title="Download log buffer as JSON"
          >
            <Download
              size={11}
              style={{ display: 'inline-block', marginRight: 5, verticalAlign: '-1px' }}
            />
            Save
          </button>
          <button
            onClick={() => clearLogs()}
            className="ap-btn ap-btn-ghost"
            style={{ padding: '6px 12px', fontSize: 10 }}
            title="Clear log buffer"
          >
            <Trash2
              size={11}
              style={{ display: 'inline-block', marginRight: 5, verticalAlign: '-1px' }}
            />
            Clear
          </button>
          <button
            onClick={onClose}
            ref={closeBtnRef}
            aria-label="Close diagnostics"
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
        <div style={{ overflow: 'auto', flex: 1, padding: '8px 18px' }}>
          {visible.length === 0 ? (
            <div style={{ fontSize: 12, color: T.textMuted, padding: '16px 0' }}>
              No log entries at this filter level.
            </div>
          ) : (
            visible
              .slice()
              .reverse()
              .map((e) => {
                const colorMap = {
                  debug: T.textMuted,
                  info: T.text,
                  warn: T.sev.medium.fg,
                  error: T.sev.critical.fg,
                };
                return (
                  <div
                    key={e.id}
                    style={{
                      padding: '6px 0',
                      borderBottom: `1px solid ${T.border}`,
                      fontFamily: fontMono,
                      fontSize: 11,
                      display: 'grid',
                      gridTemplateColumns: '90px 60px 1fr',
                      gap: 12,
                      alignItems: 'baseline',
                    }}
                  >
                    <span style={{ color: T.textMuted }}>
                      {new Date(e.ts).toLocaleTimeString(undefined, { hour12: false })}
                    </span>
                    <span
                      style={{
                        color: colorMap[e.level],
                        fontWeight: 600,
                        textTransform: 'uppercase',
                        letterSpacing: '0.05em',
                      }}
                    >
                      {e.level}
                    </span>
                    <div style={{ color: colorMap[e.level], wordBreak: 'break-word' }}>
                      <span style={{ color: T.accent }}>[{e.scope}]</span> {e.message}
                      {e.context && (
                        <pre
                          style={{
                            margin: '4px 0 0',
                            padding: '6px 8px',
                            background: T.bg,
                            border: `1px solid ${T.border}`,
                            color: T.textDim,
                            fontSize: 10,
                            whiteSpace: 'pre-wrap',
                            wordBreak: 'break-word',
                          }}
                        >
                          {typeof e.context === 'string'
                            ? e.context
                            : JSON.stringify(e.context, null, 2)}
                        </pre>
                      )}
                    </div>
                  </div>
                );
              })
          )}
        </div>
      </div>
    </>
  );
}
