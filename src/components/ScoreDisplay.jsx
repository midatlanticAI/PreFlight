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
