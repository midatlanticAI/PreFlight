// scripts/gen-sitemap.mjs
//
// Generates public/sitemap.xml from the real route surface so Google (and the
// AI crawlers we allow in robots.txt) can discover every page, not just the
// homepage. Runs automatically before every build via the "prebuild" script,
// so the sitemap can never drift behind the Learn library as it grows.
//
// Zero external deps, matching learn-content.js: a minimal frontmatter reader
// pulls `slug` / `draft` / `last_updated` from each Markdown file. Draft pages
// are excluded (they never ship, and must not be advertised to crawlers).

import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BASE = 'https://preflight.midatlantic.ai';
const TODAY = new Date().toISOString().slice(0, 10);

// Static content/marketing routes (App.jsx). Settings tabs and the catch-all
// are intentionally excluded: they are app chrome, not indexable content.
const STATIC = [
  { path: '/', priority: '1.0', changefreq: 'weekly', alternates: true },
  { path: '/learn', priority: '0.9', changefreq: 'weekly' },
  { path: '/learn/patterns', priority: '0.8', changefreq: 'weekly' },
  { path: '/learn/incidents', priority: '0.7', changefreq: 'weekly' },
  { path: '/learn/shapes', priority: '0.8', changefreq: 'weekly' },
  { path: '/learn/resources', priority: '0.6', changefreq: 'monthly' },
  { path: '/learn/owasp', priority: '0.7', changefreq: 'monthly' },
  { path: '/learn/how-it-works', priority: '0.6', changefreq: 'monthly' },
  { path: '/learn/glossary', priority: '0.6', changefreq: 'monthly' },
  { path: '/learn/breakers', priority: '0.6', changefreq: 'monthly' },
  { path: '/privacy', priority: '0.3', changefreq: 'yearly' },
  { path: '/terms', priority: '0.3', changefreq: 'yearly' },
];

// type -> route segment + sitemap weighting
const CONTENT = [
  { dir: 'patterns', seg: 'patterns', priority: '0.7', changefreq: 'monthly' },
  { dir: 'incidents', seg: 'incidents', priority: '0.6', changefreq: 'monthly' },
  { dir: 'shapes', seg: 'shapes', priority: '0.7', changefreq: 'monthly' },
];

// Minimal frontmatter read: only the keys the sitemap needs. Mirrors the
// `---\n<yaml>\n---` shape that learn-content.js enforces at runtime.
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

const xmlEscape = (s) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function urlBlock({ path, priority, changefreq, lastmod, alternates }) {
  const loc = `${BASE}${path}`;
  const alt = alternates
    ? `\n    <xhtml:link rel="alternate" hreflang="en" href="${loc}" />` +
      `\n    <xhtml:link rel="alternate" hreflang="x-default" href="${loc}" />`
    : '';
  return `  <url>
    <loc>${xmlEscape(loc)}</loc>
    <lastmod>${lastmod || TODAY}</lastmod>
    <changefreq>${changefreq}</changefreq>
    <priority>${priority}</priority>${alt}
  </url>`;
}

const urls = [];
let skipped = 0;

for (const r of STATIC) urls.push(urlBlock(r));

for (const c of CONTENT) {
  const dir = join(ROOT, 'src', 'learn', c.dir);
  for (const f of readdirSync(dir).filter((n) => n.endsWith('.md')).sort()) {
    const fm = readFrontmatter(join(dir, f));
    if (fm.draft) {
      skipped += 1;
      continue;
    }
    const slug = fm.slug || basename(f, '.md');
    urls.push(
      urlBlock({
        path: `/learn/${c.seg}/${slug}`,
        priority: c.priority,
        changefreq: c.changefreq,
        lastmod: fm.last_updated,
      })
    );
  }
}

const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xhtml="http://www.w3.org/1999/xhtml">
${urls.join('\n')}
</urlset>
`;

writeFileSync(join(ROOT, 'public', 'sitemap.xml'), xml, 'utf8');
console.log(
  `sitemap.xml: ${urls.length} urls (${STATIC.length} static + ${urls.length - STATIC.length} content, ${skipped} draft skipped)`
);
