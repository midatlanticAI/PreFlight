// src/lib/learn-content.js
// Build-time loader for src/learn/**/*.md. Vite's `import.meta.glob` reads every
// markdown file in the Learn directory and bundles their raw text. gray-matter
// parses the YAML frontmatter on the way through; the resulting registry is a
// flat array of `{ slug, type, title, summary, last_updated, draft, body, ...frontmatter }`
// records that the Learn page indexes and renders against.
//
// Schema enforced at parse time:
//   title        string, required
//   slug         string, required (kebab-case; should match filename)
//   type         "manifesto" | "pattern" | "incident" | "shape", required
//   last_updated YYYY-MM-DD, required
//   draft        boolean, default false
//   summary      string, optional
//   related_probe_ids, related_incident_slugs, sources — optional
//
// Files that fail validation surface as a console warning; they don't crash
// the build. That keeps the markdown editing surface forgiving — a missing
// frontmatter key gives feedback in the browser console rather than a build
// break.

import matter from 'gray-matter';
import { log } from './logger.js';

const VALID_TYPES = new Set(['manifesto', 'pattern', 'incident', 'shape']);

// `import.meta.glob` with `eager: true` resolves at build time. The `?raw` query
// gives us the literal source string; gray-matter handles the frontmatter split.
// Vite scans `src/learn/**/*.md` and produces an object keyed by path.
const RAW_MODULES = import.meta.glob('../learn/**/*.md', {
  query: '?raw',
  import: 'default',
  eager: true,
});

function parseEntry(path, raw) {
  try {
    const { data, content } = matter(raw);
    const slug = data.slug || path.split('/').pop().replace(/\.md$/, '');
    if (!data.title) {
      log.warn(`[learn] ${path}: missing required \`title\` frontmatter`);
      return null;
    }
    if (!VALID_TYPES.has(data.type)) {
      log.warn(
        `[learn] ${path}: invalid \`type\` "${data.type}", expected one of ${[...VALID_TYPES].join(', ')}`
      );
      return null;
    }
    return {
      slug,
      type: data.type,
      title: data.title,
      summary: data.summary || '',
      last_updated: data.last_updated || null,
      draft: !!data.draft,
      related_probe_ids: Array.isArray(data.related_probe_ids) ? data.related_probe_ids : [],
      related_incident_slugs: Array.isArray(data.related_incident_slugs)
        ? data.related_incident_slugs
        : [],
      sources: Array.isArray(data.sources) ? data.sources : [],
      body: content.trim(),
      _path: path,
    };
  } catch (e) {
    log.warn(`[learn] ${path}: parse failed`, e?.message);
    return null;
  }
}

export const LEARN_ENTRIES = Object.entries(RAW_MODULES)
  .map(([path, raw]) => parseEntry(path, typeof raw === 'string' ? raw : ''))
  .filter(Boolean);

// Helpers that the index views and the per-slug page use.
export function getManifesto() {
  return LEARN_ENTRIES.find((e) => e.type === 'manifesto');
}

export function getByType(type) {
  return LEARN_ENTRIES.filter((e) => e.type === type).sort((a, b) =>
    a.title.localeCompare(b.title)
  );
}

export function getBySlug(slug) {
  return LEARN_ENTRIES.find((e) => e.slug === slug);
}

// Resolves a probe's learn_more_slug to the actual entry IF it exists AND is
// not a draft. Returns null otherwise so FindingCard can hide the link cleanly.
export function resolvePatternForProbe(slug) {
  if (!slug) return null;
  const entry = getBySlug(slug);
  if (!entry) return null;
  if (entry.draft) return null;
  if (entry.type !== 'pattern') return null;
  return entry;
}
