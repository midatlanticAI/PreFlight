// Regression test for the v0.4 nav restructure. The old "floating Bug + AI" corner buttons
// were removed and the underlying functionality lifted into Settings → Diagnostics and
// Settings → Explain & Verify. If a future commit accidentally reintroduces the floating
// pattern (the icons themselves are still imported elsewhere as Settings tab icons), this
// test catches it before it ships.
//
// Static check, not a render test — we grep App.jsx for the specific patterns that
// indicated the old floating buttons. Cheap, deterministic, and survives prop refactors.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const APP_JSX = readFileSync(join(process.cwd(), 'src', 'App.jsx'), 'utf-8');

describe('No-floating-buttons regression (v0.4)', () => {
  it('App.jsx does NOT import the Bug lucide icon (was the floating diagnostics)', () => {
    // The Bug icon currently lives only inside Settings tab nav icons, NOT in App.jsx.
    // Re-introducing the import here would signal someone bringing the corner button back.
    const importMatch = APP_JSX.match(/^import\s*\{[^}]*\bBug\b[^}]*\}\s*from\s*'lucide-react'/m);
    expect(importMatch).toBeNull();
  });

  it('App.jsx does NOT render a fixed-position bottom-right button', () => {
    // The old pattern was `position: 'fixed', right: 18, bottom: 18` for diagnostics
    // and `right: 18, bottom: 68` for AI. Any future fixed bottom-right rule is a regression.
    expect(APP_JSX).not.toMatch(/position:\s*['"]fixed['"][\s\S]{0,200}right:\s*18/);
    expect(APP_JSX).not.toMatch(/right:\s*18[\s\S]{0,200}bottom:\s*(?:18|68)/);
  });

  it('App.jsx does NOT reference setAiSettingsOpen / setDiagOpen (old modal/drawer state)', () => {
    // These state setters powered the floating buttons → modal/drawer dance. They were
    // removed when AI settings moved to /settings/ai and Diagnostics moved to
    // /settings/diagnostics. The setter names would only return if someone rewired the
    // old modal pattern.
    expect(APP_JSX).not.toMatch(/\bsetAiSettingsOpen\b/);
    expect(APP_JSX).not.toMatch(/\bsetDiagOpen\b/);
  });

  it('App.jsx does NOT import AISettingsModal or DiagnosticsDrawer (deleted in v0.4)', () => {
    expect(APP_JSX).not.toMatch(/from\s*['"][^'"]*\/AISettingsModal/);
    expect(APP_JSX).not.toMatch(/from\s*['"][^'"]*\/DiagnosticsDrawer/);
  });

  it('Settings tab nav still imports the icons (sanity check: not a blanket icon ban)', () => {
    // The Bug icon stayed in the Settings → Diagnostics tab icon. We just don't want
    // it back in App.jsx as a floating control. This sanity check confirms we haven't
    // over-corrected.
    const diagTab = readFileSync(
      join(process.cwd(), 'src', 'components', 'settings', 'DiagnosticsTab.jsx'),
      'utf-8'
    );
    // DiagnosticsTab uses Activity / Copy / Download / Trash2 internally; that's fine
    expect(diagTab).toMatch(/import\s*\{[^}]*\}\s*from\s*'lucide-react'/);
  });
});
