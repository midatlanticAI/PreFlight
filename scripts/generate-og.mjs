// scripts/generate-og.mjs
// Render public/og-card.svg → public/og-card.png at 1200×630 using sharp.
// Run with `npm run og`. The PNG is what social platforms actually fetch — Twitter / X,
// LinkedIn, Facebook, iMessage, Discord, and Slack all skip SVG og:image. We keep both
// files in the repo: the SVG is the source of truth (editable design), the PNG is what
// gets shipped and referenced in <meta property="og:image">.
//
// Re-run this script whenever og-card.svg changes; the PNG is intentionally NOT auto-
// generated at build time (build runs in CI and on Cloudflare Pages, where pulling sharp
// would add ~30 MB to the image and slow down every deploy). Generate locally + commit.

import sharp from 'sharp';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repo = join(__dirname, '..');
const svgPath = join(repo, 'public', 'og-card.svg');
const pngPath = join(repo, 'public', 'og-card.png');

const svg = readFileSync(svgPath);
const buf = await sharp(svg, { density: 144 })
  .resize(1200, 630, { fit: 'contain' })
  .png({ quality: 92, compressionLevel: 9 })
  .toBuffer();

writeFileSync(pngPath, buf);
console.log(`wrote ${pngPath} (${buf.length} bytes)`);
