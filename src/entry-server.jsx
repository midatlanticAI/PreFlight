// src/entry-server.jsx
//
// Server render entry used only by scripts/prerender.mjs (via Vite's
// ssrLoadModule). It renders the SSR-safe content routes to static HTML so
// crawlers index real text per URL. The client bundle is unchanged and still
// boots the full lazy SPA; the browser mounts fresh over this markup
// (prerender-for-bots, CSR-for-users), so there is no hydration contract to
// keep and no client behavior change.
//
// "/" renders a static, browser-global-free HomeOverview (not the live
// AuditView, which reads browser globals and cannot be SSR'd). This gives the
// crawlable entry point real, machine-readable content; the client still boots
// the full AuditView and mounts fresh over this markup. "/settings/*" stays
// excluded (browser-global-dependent, no indexable content); it still gets a
// correct per-route <head> from src/lib/seo.js. Unmatched paths render empty.
//
// Content views are imported directly (not via App.jsx's lazyNamed) because
// renderToString is synchronous and does not resolve React.lazy / Suspense.
// These are the same component modules the client uses, so content cannot
// drift between server and client.

import { renderToString } from 'react-dom/server';
import { StaticRouter } from 'react-router-dom/server';
import { Routes, Route } from 'react-router-dom';

import { HomeOverview } from './components/HomeOverview.jsx';
import { LearnPage } from './components/learn/LearnPage.jsx';
import { ManifestoView } from './components/learn/ManifestoView.jsx';
import { IndexView } from './components/learn/IndexView.jsx';
import { EntryView } from './components/learn/EntryView.jsx';
import { ResourcesView } from './components/learn/ResourcesView.jsx';
import { OwaspCoverageView } from './components/learn/OwaspCoverageView.jsx';
import { GlossaryView } from './components/learn/GlossaryView.jsx';
import { BreakersInfoView } from './components/learn/BreakersInfoView.jsx';
import { HowToView } from './components/learn/HowToView.jsx';
import { SocialView } from './components/learn/SocialView.jsx';
import { TheClimbView } from './components/learn/TheClimbView.jsx';
import { FlightSchoolView } from './components/learn/FlightSchoolView.jsx';
import { ToolsView } from './components/learn/ToolsView.jsx';
import { PrivacyView } from './components/PrivacyView.jsx';
import { TermsView } from './components/TermsView.jsx';

export function render(url) {
  return renderToString(
    <StaticRouter location={url}>
      <div className="ap-prerender">
        <Routes>
          <Route path="/" element={<HomeOverview />} />
          <Route path="/learn" element={<LearnPage />}>
            <Route index element={<ManifestoView />} />
            <Route path="how-it-works" element={<HowToView />} />
            <Route path="the-climb" element={<TheClimbView />} />
            <Route path="flight-school" element={<FlightSchoolView />} />
            <Route path="tools" element={<ToolsView />} />
            <Route path="patterns" element={<IndexView type="pattern" />} />
            <Route path="patterns/:slug" element={<EntryView />} />
            <Route path="incidents" element={<IndexView type="incident" />} />
            <Route path="incidents/:slug" element={<EntryView />} />
            <Route path="shapes" element={<IndexView type="shape" />} />
            <Route path="shapes/:slug" element={<EntryView />} />
            <Route path="resources" element={<ResourcesView />} />
            <Route path="social" element={<SocialView />} />
            <Route path="owasp" element={<OwaspCoverageView />} />
            <Route path="glossary" element={<GlossaryView />} />
            <Route path="breakers" element={<BreakersInfoView />} />
          </Route>
          <Route path="/privacy" element={<PrivacyView />} />
          <Route path="/terms" element={<TermsView />} />
          <Route path="*" element={null} />
        </Routes>
      </div>
    </StaticRouter>
  );
}
