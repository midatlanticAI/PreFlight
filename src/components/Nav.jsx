// src/components/Nav.jsx
// Top nav bar with three destinations: Audit (`/`), Learn (`/learn`), Settings (`/settings`).
// Uses react-router's NavLink so the active route gets the brand-orange treatment
// automatically.
//
// WCAG 2.2 sizing:
//   - 44×44 px touch target (WCAG 2.5.5 AAA / 2.5.8 AA + plenty of buffer)
//   - 14 px mixed-case label (was 11 px uppercase letterspaced — eye-fatigue heavy)
//   - 0 letter-spacing, regular UI font — readable at glance
//   - Labels visible at every viewport. Below 480 px the icons shrink slightly and the
//     padding tightens but labels never disappear (mystery-meat icon nav fails 3.2.3).

import { NavLink } from 'react-router-dom';
import { ShieldCheck, BookOpen, Settings as SettingsIcon } from 'lucide-react';
import { T, fontUI } from '../lib/theme.js';

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
      className="ap-primary-nav"
    >
      {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
        <NavLink
          key={to}
          to={to}
          end={end}
          style={({ isActive }) => ({
            display: 'inline-flex',
            alignItems: 'center',
            gap: 10,
            padding: '12px 18px',
            color: isActive ? T.bg : T.text,
            background: isActive ? T.accent : 'transparent',
            border: 'none',
            fontFamily: fontUI,
            fontSize: 15,
            fontWeight: 600,
            cursor: 'pointer',
            textDecoration: 'none',
            transition: 'background 0.12s ease, color 0.12s ease',
            minHeight: 44, // WCAG 2.5.5 AAA touch-target
          })}
          aria-current={undefined /* NavLink injects this automatically when active */}
        >
          {({ isActive }) => (
            <>
              <Icon size={16} aria-hidden="true" />
              <span className="ap-nav-label" aria-current={isActive ? 'page' : undefined}>
                {label}
              </span>
            </>
          )}
        </NavLink>
      ))}
      <style>{`
        @media (max-width: 480px) {
          .ap-primary-nav a {
            padding: 10px 12px !important;
            font-size: 14px !important;
            gap: 6px !important;
          }
        }
      `}</style>
    </nav>
  );
}
