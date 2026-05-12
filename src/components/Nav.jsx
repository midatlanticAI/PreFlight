// src/components/Nav.jsx
// Top nav bar with three destinations: Audit (`/`), Learn (`/learn`), Settings (`/settings`).
// Uses react-router's NavLink so the active route gets the brand-orange treatment
// automatically. Collapses to icon-only labels below 640 px.

import { NavLink } from 'react-router-dom';
import { ShieldCheck, BookOpen, Settings as SettingsIcon } from 'lucide-react';
import { T, fontEyebrow, fontMono } from '../lib/theme.js';

const NAV_ITEMS = [
  { to: '/', label: 'Audit', icon: ShieldCheck, end: true },
  { to: '/learn', label: 'Learn', icon: BookOpen, end: false },
  { to: '/settings', label: 'Settings', icon: SettingsIcon, end: false },
];

export function Nav() {
  return (
    <nav
      aria-label="Primary navigation"
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 4,
        background: T.panel,
        border: `1px solid ${T.border}`,
        padding: 4,
      }}
    >
      {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
        <NavLink
          key={to}
          to={to}
          end={end}
          aria-label={label}
          style={({ isActive }) => ({
            display: 'inline-flex',
            alignItems: 'center',
            gap: 8,
            padding: '8px 14px',
            color: isActive ? T.bg : T.textDim,
            background: isActive ? T.accent : 'transparent',
            border: 'none',
            fontFamily: fontMono,
            fontSize: 11,
            letterSpacing: '0.12em',
            textTransform: 'uppercase',
            fontWeight: 600,
            cursor: 'pointer',
            textDecoration: 'none',
            transition: 'background 0.12s ease, color 0.12s ease',
            minHeight: 24,
          })}
        >
          {({ isActive }) => (
            <>
              <Icon size={12} aria-hidden="true" />
              <span
                style={{
                  fontFamily: fontEyebrow,
                  fontSize: 12,
                  letterSpacing: '0.14em',
                }}
                className="ap-nav-label"
                aria-current={isActive ? 'page' : undefined}
              >
                {label}
              </span>
            </>
          )}
        </NavLink>
      ))}
      <style>{`
        @media (max-width: 640px) {
          .ap-nav-label { display: none; }
        }
      `}</style>
    </nav>
  );
}
