import React from 'react';
import { log, exportLogs } from './lib/logger.js';

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null, info: null, resetKey: 0 };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    this.setState({ info });
    log.error('React render crash', {
      message: error?.message,
      stack: error?.stack,
      componentStack: info?.componentStack,
    });
  }

  handleReset = () => {
    // Bump resetKey so the children remount with fresh state. Without this, a re-render of the
    // same broken subtree with the same props can re-throw immediately and trap the user in a loop.
    this.setState((s) => ({ error: null, info: null, resetKey: s.resetKey + 1 }));
  };

  handleCopyDiagnostics = async () => {
    const payload = JSON.stringify(
      {
        time: new Date().toISOString(),
        userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : null,
        error: this.state.error
          ? {
              name: this.state.error.name,
              message: this.state.error.message,
              stack: this.state.error.stack,
            }
          : null,
        componentStack: this.state.info?.componentStack || null,
        logs: JSON.parse(exportLogs()),
      },
      null,
      2
    );
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(payload);
      }
    } catch (e) {
      log.debug('error-boundary: copy diagnostics failed', { error: e?.message });
    }
  };

  render() {
    if (!this.state.error) {
      // key={resetKey} forces a fresh subtree on Reset so a same-input re-throw is avoided.
      return <React.Fragment key={this.state.resetKey}>{this.props.children}</React.Fragment>;
    }
    return (
      <div
        style={{
          minHeight: '100vh',
          background: '#0a1226',
          color: '#f5f7fa',
          fontFamily: "'JetBrains Mono', ui-monospace, monospace",
          padding: 40,
          display: 'flex',
          alignItems: 'flex-start',
          justifyContent: 'center',
        }}
      >
        {/* Scoped focus + reduced-motion styles for the boundary fallback.
            The global :focus-visible rule in App.jsx is scoped to .ap-app, which
            doesn't apply here — without this, keyboard users get only the browser
            default outline on these recovery buttons (WCAG 2.4.7 / 2.4.13). */}
        <style>{`
          .ap-boundary *:focus-visible {
            outline: 2px solid #f26b1f;
            outline-offset: 2px;
          }
          .ap-boundary button { min-height: 24px; min-width: 24px; }
          @media (prefers-reduced-motion: reduce) {
            .ap-boundary *, .ap-boundary *::before, .ap-boundary *::after {
              animation-duration: 0.01ms !important;
              transition-duration: 0.01ms !important;
            }
          }
        `}</style>
        <div
          className="ap-boundary"
          role="alertdialog"
          aria-label="Application error"
          aria-live="assertive"
          style={{
            maxWidth: 800,
            width: '100%',
            background: '#11192e',
            border: '1px solid #fb7185',
            borderLeft: '4px solid #fb7185',
            padding: 28,
          }}
        >
          <div
            style={{
              fontSize: 11,
              letterSpacing: '0.18em',
              textTransform: 'uppercase',
              color: '#fb7185',
              marginBottom: 12,
            }}
          >
            UNRECOVERABLE RENDER ERROR
          </div>
          <h1
            style={{
              margin: '0 0 16px',
              fontFamily: "'Instrument Serif', Georgia, serif",
              fontStyle: 'italic',
              fontSize: 36,
              fontWeight: 400,
              color: '#f5f7fa',
            }}
          >
            Something broke while drawing the UI.
          </h1>
          <p style={{ color: '#a8b1c5', fontSize: 13, lineHeight: 1.7, marginBottom: 16 }}>
            The error and a copy of the recent log buffer are below. The "Copy Diagnostics" button
            grabs everything as JSON for sharing. "Try Again" attempts to re-render — if the same
            input still triggers it, refresh the page or clear localStorage.
          </p>
          <div
            style={{
              background: '#0a1226',
              border: '1px solid #1f2a44',
              padding: 14,
              marginBottom: 14,
              fontSize: 12,
            }}
          >
            <div style={{ color: '#fb7185', marginBottom: 6 }}>
              {this.state.error.name}: {this.state.error.message}
            </div>
            {this.state.error.stack && (
              <pre
                style={{
                  margin: 0,
                  color: '#a8b1c5',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                  fontSize: 11,
                  lineHeight: 1.5,
                  maxHeight: 240,
                  overflowY: 'auto',
                }}
              >
                {this.state.error.stack}
              </pre>
            )}
          </div>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            <button
              onClick={this.handleReset}
              style={{
                background: '#f26b1f',
                color: '#0a1226',
                border: 'none',
                padding: '10px 18px',
                fontFamily: 'inherit',
                fontSize: 12,
                fontWeight: 600,
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                cursor: 'pointer',
              }}
            >
              Try Again
            </button>
            <button
              onClick={this.handleCopyDiagnostics}
              style={{
                background: 'transparent',
                color: '#a8b1c5',
                border: '1px solid #1f2a44',
                padding: '10px 18px',
                fontFamily: 'inherit',
                fontSize: 12,
                fontWeight: 600,
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                cursor: 'pointer',
              }}
            >
              Copy Diagnostics
            </button>
            <button
              onClick={() => window.location.reload()}
              style={{
                background: 'transparent',
                color: '#a8b1c5',
                border: '1px solid #1f2a44',
                padding: '10px 18px',
                fontFamily: 'inherit',
                fontSize: 12,
                fontWeight: 600,
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                cursor: 'pointer',
              }}
            >
              Reload Page
            </button>
          </div>
        </div>
      </div>
    );
  }
}
