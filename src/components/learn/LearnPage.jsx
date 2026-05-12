// src/components/learn/LearnPage.jsx
// Top-level Learn route. Sub-tab strip ( Vibe-Aware | Patterns | Field Reports | Shapes )
// plus an <Outlet/> for the nested routes. Each sub-tab is its own URL so deep-links
// land on the right view without a page reload.
//
// The sub-routes wired up here:
//   /learn                          → ManifestoView (Vibe-Aware tab)
//   /learn/patterns                 → IndexView with type="pattern"
//   /learn/patterns/:slug           → EntryView
//   /learn/incidents                → IndexView with type="incident"
//   /learn/incidents/:slug          → EntryView
//   /learn/shapes                   → IndexView with type="shape"
//   /learn/shapes/:slug             → EntryView

import { NavLink, Outlet } from 'react-router-dom';
import { T, fontUI } from '../../lib/theme.js';

const SUB_TABS = [
  { to: '/learn', label: 'Vibe-Aware', end: true },
  { to: '/learn/patterns', label: 'Patterns', end: false },
  { to: '/learn/incidents', label: 'Field Reports', end: false },
  { to: '/learn/shapes', label: 'Shapes', end: false },
  { to: '/learn/resources', label: 'Resources', end: false },
];

export function LearnPage() {
  return (
    <div className="ap-fade-in">
      <header style={{ marginBottom: 20 }}>
        <div className="ap-eyebrow" style={{ marginBottom: 8 }}>
          PRE-FLIGHT LEARN
        </div>
        <h1
          className="ap-display"
          style={{
            margin: '0 0 8px',
            fontSize: 39,
            fontWeight: 700,
            color: T.text,
            letterSpacing: '-0.01em',
          }}
        >
          A library for vibers building vibeware.
        </h1>
        <p style={{ fontSize: 15, color: T.textDim, lineHeight: 1.7, margin: 0, maxWidth: 720 }}>
          Pre-Flight catches security issues. This is where we explain them — the patterns we look
          for, the real-world incidents behind the threat-intel, and the architecture shapes that
          shape (or break) your security posture. Read once, build safer forever.
        </p>
      </header>

      <nav
        aria-label="Learn sub-sections"
        style={{
          display: 'flex',
          gap: 4,
          background: T.panel,
          border: `1px solid ${T.border}`,
          padding: 4,
          marginBottom: 24,
          overflowX: 'auto',
          scrollbarWidth: 'thin',
        }}
        className="ap-learn-subnav"
      >
        {SUB_TABS.map(({ to, label, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            style={({ isActive }) => ({
              padding: '12px 16px',
              color: isActive ? T.bg : T.text,
              background: isActive ? T.accent : 'transparent',
              border: 'none',
              fontFamily: fontUI,
              fontSize: 15,
              fontWeight: 600,
              cursor: 'pointer',
              textDecoration: 'none',
              whiteSpace: 'nowrap',
              minHeight: 44, // WCAG 2.5.5 AAA touch target
              display: 'inline-flex',
              alignItems: 'center',
            })}
          >
            {label}
          </NavLink>
        ))}
      </nav>
      <style>{`
        @media (max-width: 480px) {
          .ap-learn-subnav a {
            padding: 10px 12px !important;
            font-size: 14px !important;
          }
        }
      `}</style>

      <Outlet />
    </div>
  );
}
