// One-shot script that bumps every fontSize / font-size value in the codebase by 8%.
// Run with: node scripts/bump-fontsize.mjs
//
// Transformations applied:
//   - `fontSize: 12`       -> `fontSize: 13`      (React inline number; round to nearest int)
//   - `fontSize: '12px'`   -> `fontSize: '13px'`  (px-suffixed string)
//   - `font-size: 12px`    -> `font-size: 13px`   (CSS)
//   - `font-size: 1.2rem`  -> `font-size: 1.296rem` (rem; keep decimals, round to 3 places)
//   - `clamp(20px, ..., 48px)` -> clamp(22px, ..., 52px) (multiply each px term inside clamp)
//
// Skipped:
//   - This script itself (filename guard)
//   - Test files (must keep deterministic numbers)
//   - Anything under node_modules / dist / public / docs
//   - Values inside `letterSpacing`, `lineHeight`, `padding`, `margin`, `gap`, etc.
//     (only matches `fontSize:` and `font-size:` literally)

import { readdirSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { join, extname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const ROOT = join(__filename, '..', '..');
const SCALE = 1.08;
const TARGET_EXTS = new Set(['.js', '.jsx', '.ts', '.tsx', '.css', '.html']);
const SKIP_DIRS = new Set(['node_modules', 'dist', 'public', 'docs', '.git']);
const SKIP_FILES = new Set([basename(__filename)]);

function isTestFile(name) {
  return /\.(test|spec)\.[jt]sx?$/.test(name);
}

function scalePx(num) {
  return Math.round(parseFloat(num) * SCALE);
}

function scaleRem(num) {
  return +(parseFloat(num) * SCALE).toFixed(3);
}

function transform(content) {
  let changed = 0;
  let out = content;

  // React inline: `fontSize: 12` or `fontSize:12` (whole numbers only).
  out = out.replace(/fontSize:\s*(\d+(?:\.\d+)?)\b(?![a-zA-Z%])/g, (match, num) => {
    const newVal = scalePx(num);
    if (String(newVal) === num) return match;
    changed += 1;
    return `fontSize: ${newVal}`;
  });

  // React inline px string: `fontSize: '12px'` or `fontSize: "12px"`.
  out = out.replace(/fontSize:\s*(['"])(\d+(?:\.\d+)?)px\1/g, (match, q, num) => {
    changed += 1;
    return `fontSize: ${q}${scalePx(num)}px${q}`;
  });

  // CSS px: `font-size: 12px;`.
  out = out.replace(/font-size:\s*(\d+(?:\.\d+)?)px/g, (match, num) => {
    changed += 1;
    return `font-size: ${scalePx(num)}px`;
  });

  // CSS rem: `font-size: 1.2rem;`.
  out = out.replace(/font-size:\s*(\d+(?:\.\d+)?)rem/g, (match, num) => {
    changed += 1;
    return `font-size: ${scaleRem(num)}rem`;
  });

  // clamp() px values inside fontSize / font-size declarations.
  // We need to find each clamp(...) following fontSize: or font-size:, then scale every Npx
  // inside the parens.
  out = out.replace(
    /(font[Ss]ize\s*:\s*['"]?)clamp\(([^)]+)\)/g,
    (match, prefix, args) => {
      const scaledArgs = args.replace(/(\d+(?:\.\d+)?)px/g, (m, n) => {
        changed += 1;
        return `${scalePx(n)}px`;
      });
      return `${prefix}clamp(${scaledArgs})`;
    }
  );

  return { out, changed };
}

function walk(dir) {
  const entries = readdirSync(dir);
  for (const name of entries) {
    if (SKIP_DIRS.has(name)) continue;
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) {
      walk(full);
    } else {
      if (SKIP_FILES.has(name)) continue;
      if (isTestFile(name)) continue;
      if (!TARGET_EXTS.has(extname(name))) continue;

      const original = readFileSync(full, 'utf8');
      const { out, changed } = transform(original);
      if (changed > 0 && out !== original) {
        writeFileSync(full, out, 'utf8');
        console.log(`${full} - ${changed} change(s)`);
      }
    }
  }
}

walk(join(ROOT, 'src'));
console.log('Done.');
