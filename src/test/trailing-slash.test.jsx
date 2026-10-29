// Pins for the trailing-slash rule (2026-10-28).
//
// Search Console reported 30 "Page with redirect" URLs and 12 "Discovered,
// currently not indexed" on the Learn tree: every internal link pointed at
// the no-slash form of a route, and the host 308s that form to the slash form
// it actually serves. The helper, the Link/NavLink wrappers and the location
// normaliser make the hrefs, the address bar, the canonical and the sitemap
// name the same URL.

import { describe, it, expect } from 'vitest';
import React, { act } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createRoot } from 'react-dom/client';
import { MemoryRouter, Routes, Route, useLocation } from 'react-router-dom';
import { slashPath, withTrailingSlash } from '../lib/trailing-slash.js';
import { Link, NavLink } from '../components/RouterLink.jsx';
import { TrailingSlashRedirect } from '../components/TrailingSlashRedirect.jsx';

globalThis.IS_REACT_ACT_ENVIRONMENT = true;

describe('slashPath', () => {
  it('adds the slash to a route path', () => {
    expect(slashPath('/learn')).toBe('/learn/');
    expect(slashPath('/learn/patterns/weak-cryptography')).toBe(
      '/learn/patterns/weak-cryptography/'
    );
  });

  it('leaves the root, slashed paths and files alone', () => {
    expect(slashPath('/')).toBe('/');
    expect(slashPath('/learn/')).toBe('/learn/');
    expect(slashPath('/llms.txt')).toBe('/llms.txt');
    expect(slashPath('/sitemap.xml')).toBe('/sitemap.xml');
    expect(slashPath('/assets/vendor-react-BOjDNI2S.js')).toBe('/assets/vendor-react-BOjDNI2S.js');
  });

  it('does not touch relative, external or protocol-relative targets', () => {
    expect(slashPath('patterns')).toBe('patterns');
    expect(slashPath('https://owasp.org/Top10')).toBe('https://owasp.org/Top10');
    expect(slashPath('//example.com/x')).toBe('//example.com/x');
    expect(slashPath(undefined)).toBe(undefined);
  });
});

describe('withTrailingSlash', () => {
  it('keeps query and hash after the slash', () => {
    expect(withTrailingSlash('/sandbox?shape=spa')).toBe('/sandbox/?shape=spa');
    expect(withTrailingSlash('/learn/glossary#rls')).toBe('/learn/glossary/#rls');
    expect(withTrailingSlash('/learn/glossary?x=1#rls')).toBe('/learn/glossary/?x=1#rls');
  });

  it('handles the object form and passes everything else through', () => {
    expect(withTrailingSlash({ pathname: '/learn', search: '?a=1' })).toEqual({
      pathname: '/learn/',
      search: '?a=1',
    });
    expect(withTrailingSlash('#top')).toBe('#top');
    expect(withTrailingSlash('mailto:x@y.z')).toBe('mailto:x@y.z');
    expect(withTrailingSlash(null)).toBe(null);
  });
});

const markup = (el, entries = ['/']) =>
  renderToStaticMarkup(<MemoryRouter initialEntries={entries}>{el}</MemoryRouter>);

describe('RouterLink wrappers', () => {
  it('Link renders the slashed href', () => {
    const html = markup(<Link to="/learn/patterns">Patterns</Link>);
    expect(html).toContain('href="/learn/patterns/"');
  });

  it('Link keeps a query string after the slash', () => {
    const html = markup(<Link to="/sandbox?shape=spa">Try</Link>);
    expect(html).toContain('href="/sandbox/?shape=spa"');
  });

  it('NavLink renders the slashed href and is active on the slashed location', () => {
    const html = markup(
      <>
        <NavLink to="/learn" end={false} className="section">
          Learn
        </NavLink>
        <NavLink to="/learn" end className="index">
          LearnIndex
        </NavLink>
      </>,
      ['/learn/patterns/']
    );
    expect(html).toMatch(/class="section active"[^>]*href="\/learn\/"/);
    expect(html).toMatch(/class="index"[^>]*href="\/learn\/"/);
  });
});

function ShowPath() {
  const { pathname, search, hash } = useLocation();
  return <div id="loc">{pathname + search + hash}</div>;
}

async function mount(entry, routePath) {
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  await act(async () => {
    root.render(
      <MemoryRouter initialEntries={[entry]}>
        <TrailingSlashRedirect />
        <Routes>
          <Route path={routePath} element={<ShowPath />} />
        </Routes>
      </MemoryRouter>
    );
  });
  const text = host.querySelector('#loc')?.textContent;
  await act(async () => root.unmount());
  host.remove();
  return text;
}

describe('TrailingSlashRedirect', () => {
  it('replaces a no-slash location with the slashed one, keeping query and hash', async () => {
    expect(await mount('/settings/ai?tab=1#k', '/settings/ai')).toBe('/settings/ai/?tab=1#k');
  });

  it('leaves the root alone', async () => {
    expect(await mount('/', '/')).toBe('/');
  });

  it('leaves an already slashed location alone', async () => {
    expect(await mount('/learn/', '/learn')).toBe('/learn/');
  });
});
