// scripts/indexnow.mjs
//
// Tell the IndexNow engines (Bing, and through Bing the Copilot and ChatGPT
// search indexes; Yandex; Seznam) that the site's pages changed. Google does
// not use IndexNow; it reads the sitemap through Search Console. Runs from CI
// on a push to main, after the build, and never fails the build: a ping that
// does not go through is a warning.
//
//   node scripts/indexnow.mjs            ping every URL in the sitemap
//   node scripts/indexnow.mjs --dry-run  print what would be sent
//
// The key is the basename of the one 32-hex .txt file under public/. IndexNow
// verifies host control by fetching https://<host>/<key>.txt and checking that
// it contains the key, so the file is public by design and is not a secret.

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const dry = process.argv.includes('--dry-run');

const keyFile = readdirSync(join(ROOT, 'public')).find((f) => /^[0-9a-f]{32}\.txt$/.test(f));
if (!keyFile) {
  console.warn('indexnow: no key file under public/; skipped');
  process.exit(0);
}
const key = keyFile.slice(0, -4);

const sitemapPath = ['dist/sitemap.xml', 'public/sitemap.xml']
  .map((p) => join(ROOT, p))
  .find((p) => existsSync(p));
if (!sitemapPath) {
  console.warn('indexnow: no sitemap.xml; skipped');
  process.exit(0);
}
const urlList = [...readFileSync(sitemapPath, 'utf8').matchAll(/<loc>([^<]+)<\/loc>/g)].map(
  (m) => m[1]
);
if (urlList.length === 0) {
  console.warn('indexnow: sitemap has no URLs; skipped');
  process.exit(0);
}
const { host, origin } = new URL(urlList[0]);
const body = { host, key, keyLocation: `${origin}/${key}.txt`, urlList };

if (dry) {
  console.log(JSON.stringify({ ...body, urlList: `${urlList.length} urls from ${sitemapPath}` }));
  process.exit(0);
}

try {
  const res = await fetch('https://api.indexnow.org/indexnow', {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(20000),
  });
  // 200 accepted; 202 accepted, key check pending; 403 / 422 mean the key file
  // is not reachable on the live host yet (the deploy has not landed).
  const note = res.ok ? '' : ` (${(await res.text()).slice(0, 200)})`;
  console.log(`indexnow: ${res.status} for ${urlList.length} url(s)${note}`);
} catch (err) {
  console.warn('indexnow: ping failed, build unaffected:', String((err && err.message) || err));
}
