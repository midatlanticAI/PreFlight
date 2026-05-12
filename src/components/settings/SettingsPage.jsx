// src/components/settings/SettingsPage.jsx
// Top-level Settings route. Left-rail sidebar tab nav + content pane. Five tabs:
// General, Explain & Verify, Private Repos, Diagnostics, About.
//
// Each tab is a sub-route under /settings so the URL deep-links work:
//   /settings           → General (default)
//   /settings/ai        → Explain & Verify
//   /settings/repos     → Private Repos
//   /settings/diagnostics → Diagnostics
//   /settings/about     → About

import { NavLink, Outlet } from 'react-router-dom';
import { Sliders, MessageSquare, Github, Activity, Info } from 'lucide-react';
import { T, fontUI } from '../../lib/theme.js';

const SETTINGS_TABS = [
  { to: '/settings', label: 'General', icon: Sliders, end: true },
  { to: '/settings/ai', label: 'Explain & Verify', icon: MessageSquare, end: false },
  { to: '/settings/repos', label: 'Private Repos', icon: Github, end: false },
  { to: '/settings/diagnostics', label: 'Diagnostics', icon: Activity, end: false },
  { to: '/settings/about', label: 'About', icon: Info, end: false },
];

export function SettingsPage() {
  return (
    <div className="ap-fade-in">
      <header style={{ marginBottom: 20 }}>
        <div className="ap-eyebrow" style={{ marginBottom: 8 }}>
          PRE-FLIGHT SETTINGS
        </div>
        <h1
          className="ap-display"
          style={{
            margin: '0 0 8px',
            fontSize: 35,
            fontWeight: 700,
            color: T.text,
            letterSpacing: '-0.01em',
          }}
        >
          Configure Pre-Flight.
        </h1>
        <p style={{ fontSize: 14, color: T.textDim, lineHeight: 1.7, margin: 0, maxWidth: 720 }}>
          Everything Pre-Flight knows about you lives in this browser tab. These panels are the one
          place to wire up optional features (AI Explain &amp; Verify, private GitHub repos),
          inspect the live log buffer, or wipe the slate.
        </p>
      </header>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '240px minmax(0, 1fr)',
          gap: 24,
          alignItems: 'start',
        }}
        className="ap-settings-grid"
      >
        <nav
          aria-label="Settings sections"
          style={{
            background: T.panel,
            border: `1px solid ${T.border}`,
            padding: 6,
            display: 'flex',
            flexDirection: 'column',
            gap: 2,
          }}
          className="ap-settings-sidebar"
        >
          {SETTINGS_TABS.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              style={({ isActive }) => ({
                display: 'inline-flex',
                alignItems: 'center',
                gap: 10,
                padding: '12px 14px',
                color: isActive ? T.bg : T.text,
                background: isActive ? T.accent : 'transparent',
                border: 'none',
                fontFamily: fontUI,
                fontSize: 15,
                fontWeight: 600,
                cursor: 'pointer',
                textDecoration: 'none',
                minHeight: 44, // WCAG 2.5.5 AAA touch target
              })}
              className="ap-settings-tab"
            >
              <Icon size={16} aria-hidden="true" />
              {label}
            </NavLink>
          ))}
        </nav>

        <div style={{ minWidth: 0 }}>
          <Outlet />
        </div>
      </div>

      <style>{`
        @media (max-width: 760px) {
          .ap-settings-grid {
            grid-template-columns: 1fr !important;
          }
          .ap-settings-sidebar {
            flex-direction: row !important;
            overflow-x: auto;
            scrollbar-width: thin;
          }
          .ap-settings-tab {
            white-space: nowrap;
            padding: 10px 12px !important;
            font-size: 14px !important;
          }
        }
      `}</style>
    </div>
  );
}
