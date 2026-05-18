// scripts/lib/routes.mjs
//
// Single source of truth for the route surface, shared by gen-sitemap.mjs
// and prerender.mjs so the sitemap and the prerendered HTML can never
// disagree about which pages exist. Zero external deps, matching
// learn-content.js (a minimal frontmatter reader, not gray-matter).

import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

// Static content/marketing routes (App.jsx). Settings tabs and the catch-all
// are intentionally excluded: app chrome, not indexable content.
export const STATIC_ROUTES = [
  { path: '/', priority: '1.0', changefreq: 'weekly', alternates: true },
  { path: '/learn', priority: '0.9', changefreq: 'weekly' },
  { path: '/learn/patterns', priority: '0.8', changefreq: 'weekly' },
  { path: '/learn/incidents', priority: '0.7', changefreq: 'weekly' },
  { path: '/learn/shapes', priority: '0.8', changefreq: 'weekly' },
  { path: '/learn/resources', priority: '0.6', changefreq: 'monthly' },
  { path: '/learn/social', priority: '0.7', changefreq: 'weekly' },
  { path: '/learn/owasp', priority: '0.7', changefreq: 'monthly' },
  { path: '/learn/how-it-works', priority: '0.6', changefreq: 'monthly' },
  { path: '/learn/the-climb', priority: '0.8', changefreq: 'weekly' },
  { path: '/learn/flight-school', priority: '0.8', changefreq: 'weekly' },
  { path: '/learn/tools', priority: '0.7', changefreq: 'weekly' },
  { path: '/learn/glossary', priority: '0.6', changefreq: 'monthly' },
  { path: '/learn/breakers', priority: '0.6', changefreq: 'monthly' },
  { path: '/privacy', priority: '0.3', changefreq: 'yearly' },
  { path: '/terms', priority: '0.3', changefreq: 'yearly' },
];

const CONTENT_DIRS = [
  { dir: 'patterns', seg: 'patterns', priority: '0.7', changefreq: 'monthly' },
  { dir: 'incidents', seg: 'incidents', priority: '0.6', changefreq: 'monthly' },
  { dir: 'shapes', seg: 'shapes', priority: '0.7', changefreq: 'monthly' },
];

// Minimal frontmatter read: only the keys these scripts need. Mirrors the
// `---\n<yaml>\n---` shape learn-content.js enforces at runtime.
function readFrontmatter(file) {
  const text = readFileSync(file, 'utf8').replace(/\r\n/g, '\n');
  const m = text.match(/^---\n([\s\S]*?)\n---/);
  const fm = { slug: null, draft: false, last_updated: null };
  if (!m) return fm;
  for (const line of m[1].split('\n')) {
    const kv = line.match(/^(slug|draft|last_updated):\s*(.+?)\s*$/);
    if (!kv) continue;
    const val = kv[2].replace(/^["']|["']$/g, '');
    if (kv[1] === 'draft') fm.draft = val === 'true';
    else fm[kv[1]] = val;
  }
  return fm;
}

// Non-draft Learn pages as route records. Draft pages never ship and must
// not be advertised to crawlers or prerendered.
export function contentRoutes() {
  const out = [];
  for (const c of CONTENT_DIRS) {
    const dir = join(ROOT, 'src', 'learn', c.dir);
    for (const f of readdirSync(dir)
      .filter((n) => n.endsWith('.md'))
      .sort()) {
      const fm = readFrontmatter(join(dir, f));
      if (fm.draft) continue;
      const slug = fm.slug || basename(f, '.md');
      out.push({
        path: `/learn/${c.seg}/${slug}`,
        priority: c.priority,
        changefreq: c.changefreq,
        lastmod: fm.last_updated,
      });
    }
  }
  return out;
}

// Flat list of every prerenderable / indexable URL path.
export function allRoutePaths() {
  return [...STATIC_ROUTES.map((r) => r.path), ...contentRoutes().map((r) => r.path)];
}
