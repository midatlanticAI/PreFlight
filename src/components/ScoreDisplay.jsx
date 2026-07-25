// src/components/ScoreDisplay.jsx
// Three small presentational components that share a file because they sit together
// in the results header card and use the same theme constants:
//   - ScoreGauge:    big circular ring + numeric score; color tracks the risk tier
//   - CategoryBar:   horizontal mini-bar used in the per-category risk breakdown
//   - SeverityChip:  small per-severity pill used by FindingCard and the suppressed list
//
// All three are pure presentational — no state, no effects. The single styling token
// they read is `T` from src/lib/theme.js, plus riskTier() for ScoreGauge's color band.

import { T, riskTier } from '../lib/theme.js';

export function ScoreGauge({ score }) {
  const tier = riskTier(score);
  const radius = 90;
  const circ = 2 * Math.PI * radius;
  const filled = (score / 100) * circ;
  return (
    <div
      role="img"
      aria-label={`Risk score ${score} out of 100, ${tier.label}`}
      style={{ position: 'relative', width: 220, height: 220 }}
    >
      <svg
        width="220"
        height="220"
        viewBox="0 0 220 220"
        style={{ transform: 'rotate(-90deg)' }}
        aria-hidden="true"
      >
        <circle cx="110" cy="110" r={radius} fill="none" stroke={T.borderAlt} strokeWidth="2" />
        <circle
          cx="110"
          cy="110"
          r={radius}
          fill="none"
          stroke={tier.ring}
          strokeWidth="3"
          strokeDasharray={`${filled} ${circ}`}
          strokeLinecap="butt"
          style={{ transition: 'stroke-dasharray 0.8s ease-out, stroke 0.4s ease' }}
        />
      </svg>
      <div
        style={{
          position: 'absolute',
          inset: 0,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <div className="ap-eyebrow" style={{ marginBottom: 4 }}>
          SCORE
        </div>
        <div className="ap-display" style={{ fontSize: 91, lineHeight: 1, color: tier.color }}>
          {score}
        </div>
        <div className="ap-mono" style={{ fontSize: 12, color: T.textMuted, marginTop: 2 }}>
          / 100
        </div>
      </div>
    </div>
  );
}

// Per-axis scores beside the headline gauge.
//
// The gauge answers "is this safe to ship" and only security findings move it.
// Code health, accessibility and discoverability are real work, and burying
// them inside one number made a clean-but-opinionated project read as risky
// while telling nobody which kind of work was outstanding. Each axis carries
// its own count so "100" is never mistaken for a measurement that did not run.
const AXIS_LABELS = {
  security: 'Security',
  health: 'Code health',
  accessibility: 'Accessibility',
  discoverability: 'Discoverability',
};

function axisColor(score, findings) {
  if (findings === 0) return T.textMuted;
  if (score >= 90) return T.good;
  if (score >= 70) return T.sev.medium.fg;
  return T.sev.high.fg;
}

export function ScoreAxes({ scores }) {
  if (!scores) return null;
  const axes = Object.keys(AXIS_LABELS).filter((a) => scores[a]);
  if (axes.length === 0) return null;
  return (
    <div>
      <div className="ap-eyebrow" style={{ fontSize: 11, color: T.textMuted, marginBottom: 10 }}>
        BY AREA
      </div>
      {axes.map((axis) => {
        const { score, findings } = scores[axis];
        const clean = findings === 0;
        return (
          <div key={axis} style={{ marginBottom: 12 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
              <span className="ap-mono" style={{ fontSize: 13, color: T.text }}>
                {AXIS_LABELS[axis]}
              </span>
              <span
                className="ap-mono"
                style={{ fontSize: 13, color: axisColor(score, findings) }}
                title={
                  clean
                    ? 'Nothing found in this area'
                    : `${findings} finding${findings === 1 ? '' : 's'}`
                }
              >
                {clean ? 'clear' : `${score} / 100`}
              </span>
            </div>
            <div style={{ height: 4, background: T.border, position: 'relative' }}>
              <div
                style={{
                  position: 'absolute',
                  inset: '0 auto 0 0',
                  width: `${score}%`,
                  background: axisColor(score, findings),
                  transition: 'width 0.6s ease-out',
                }}
              />
            </div>
            {!clean && (
              <div className="ap-mono" style={{ fontSize: 11, color: T.textMuted, marginTop: 4 }}>
                {findings} finding{findings === 1 ? '' : 's'}
                {axis !== 'security' && ' · does not affect the risk score'}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

export function CategoryBar({ name, count, max, color }) {
  const pct = max > 0 ? (count / max) * 100 : 0;
  return (
    <div style={{ marginBottom: 14 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
        <span className="ap-mono" style={{ fontSize: 13, color: T.text }}>
          {name}
        </span>
        <span className="ap-mono" style={{ fontSize: 13, color: T.textDim }}>
          {count}
        </span>
      </div>
      <div style={{ height: 4, background: T.border, position: 'relative' }}>
        <div
          style={{
            position: 'absolute',
            left: 0,
            top: 0,
            bottom: 0,
            width: `${pct}%`,
            background: color,
            transition: 'width 0.6s ease-out',
          }}
        />
      </div>
    </div>
  );
}

export function SeverityChip({ severity }) {
  const c = T.sev[severity];
  return (
    <span
      className="ap-mono"
      style={{
        fontSize: 11,
        letterSpacing: '0.12em',
        textTransform: 'uppercase',
        color: c.fg,
        background: c.bg,
        border: `1px solid ${c.border}`,
        padding: '3px 8px',
        fontWeight: 600,
      }}
    >
      {severity}
    </span>
  );
}
