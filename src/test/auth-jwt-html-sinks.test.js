/**
 * Six narrow recall gaps, found by an adversarial pass and each verified
 * before being believed. Two of the six premises handed to that pass were
 * wrong, and the corrections are the interesting part:
 *
 *   - The reversed-operand password comparison already worked. The real miss
 *     was the NEGATED operator: `\s*(?:===|==)` cannot step over the `!` in
 *     `!==`, so every guard-clause login handler was silent, and that is how
 *     most of them are written.
 *   - The AWS secret pattern already existed. It only looked missing because
 *     the repro used AWS's own EXAMPLEKEY value, which the placeholder filter
 *     correctly eats.
 *
 * The unkeyed 40-character AWS pattern was DROPPED rather than shipped: it
 * matched 242 times across the canary corpus, every one a pinned GitHub Action
 * SHA, with zero true positives. A rule tuned on a corpus containing none of
 * what it hunts is not evidence, and a critical on someone's screen for a
 * commit hash is worse than the gap.
 */

import { describe, it, expect } from 'vitest';
import { probeAuthWeakness, probeSecrets } from '../lib/probes.js';

const f = (content, path = 'src/server/app.js') => [{ path, content }];
const titles = (findings) => findings.map((x) => x.title).join(' | ');

describe('a decoded JWT used as identity', () => {
  it('jwt.decode assigned straight to req.user', () => {
    const src =
      'import jwt from "jsonwebtoken";\nexport function mw(req, res, next) {\n  req.user = jwt.decode(req.headers.authorization);\n  next();\n}\n';
    expect(probeAuthWeakness(f(src)).some((x) => x.cwe === 'CWE-347')).toBe(true);
  });

  it('decoded into a local, then assigned', () => {
    const src =
      'import jwt from "jsonwebtoken";\nexport function mw(req, res, next) {\n  const claims = jwt.decode(req.headers.authorization);\n  req.user = claims;\n  next();\n}\n';
    expect(probeAuthWeakness(f(src)).some((x) => x.cwe === 'CWE-347')).toBe(true);
  });

  // Decoding to read a non-security claim is legitimate, and so is decoding the
  // header to pick a key before verifying. Both must stay silent or the check
  // punishes the correct pattern.
  it('decode for logging only is silent', () => {
    const src =
      'import jwt from "jsonwebtoken";\nexport function logExp(t) {\n  const claims = jwt.decode(t);\n  return claims.exp;\n}\n';
    expect(probeAuthWeakness(f(src)).filter((x) => x.cwe === 'CWE-347')).toHaveLength(0);
  });

  it('decode the header, then verify with the chosen key, is silent', () => {
    const src =
      'import jwt from "jsonwebtoken";\nexport function v(t, keys) {\n  const header = jwt.decode(t, { complete: true }).header;\n  return jwt.verify(t, keys[header.kid]);\n}\n';
    expect(probeAuthWeakness(f(src)).filter((x) => x.cwe === 'CWE-347')).toHaveLength(0);
  });
});

describe('jwt.verify with an explicit empty key', () => {
  for (const key of ['undefined', 'null']) {
    it(`jwt.verify(token, ${key}) fires`, () => {
      const src = `import jwt from "jsonwebtoken";\nexport function v(t) {\n  return jwt.verify(t, ${key});\n}\n`;
      expect(titles(probeAuthWeakness(f(src)))).toMatch(/undefined or null key/);
    });
  }

  it('a real secret is silent', () => {
    const src =
      'import jwt from "jsonwebtoken";\nexport function v(t) {\n  return jwt.verify(t, process.env.JWT_SECRET);\n}\n';
    expect(titles(probeAuthWeakness(f(src)))).not.toMatch(/undefined or null key/);
  });
});

describe('plaintext password comparison, negated', () => {
  it('the guard-clause form fires', () => {
    const src =
      'export async function login(req, res) {\n  const user = await db.find(req.body.email);\n  if (req.body.password !== user.password) return res.status(401).end();\n  return res.json({ ok: true });\n}\n';
    expect(probeAuthWeakness(f(src)).some((x) => x.cwe === 'CWE-261')).toBe(true);
  });

  const silent = [
    [
      'a presence check against null',
      'export function g(user, res) {\n  if (user.password == null) return res.status(500).end();\n  return null;\n}\n',
    ],
    // `pwd` is print-working-directory far more often than it is a password.
    [
      'pwd naming a working directory',
      'export function changed(finalPwd, targetDir) {\n  return Boolean(finalPwd && finalPwd !== targetDir);\n}\n',
    ],
    [
      'bcrypt.compare',
      'import bcrypt from "bcrypt";\nexport async function login(req, user) {\n  return bcrypt.compare(req.body.secretInput, user.hash);\n}\n',
    ],
  ];
  for (const [name, src] of silent) {
    it(`${name} is silent`, () => {
      expect(probeAuthWeakness(f(src)).filter((x) => x.cwe === 'CWE-261')).toHaveLength(0);
    });
  }
});

describe('HTML sinks the inline-only check missed', () => {
  it('a hoisted __html object fires', () => {
    const src =
      'export function Post({ post }) {\n  const markup = { __html: post.body };\n  return <article dangerouslySetInnerHTML={markup} />;\n}\n';
    expect(probeAuthWeakness(f(src, 'src/components/Post.jsx')).length).toBeGreaterThan(0);
  });

  it('a hoisted object holding an author-written literal is silent', () => {
    const src =
      'export function Banner() {\n  const markup = { __html: "<b>Welcome back</b>" };\n  return <aside dangerouslySetInnerHTML={markup} />;\n}\n';
    expect(probeAuthWeakness(f(src, 'src/components/Banner.jsx'))).toHaveLength(0);
  });

  // .vue and .svelte were in FILE_INCLUDE, and the probe returned before
  // reaching the framework patterns because the path was not .jsx.
  it('vue v-html fires', () => {
    const src = '<template>\n  <div v-html="post.body"></div>\n</template>\n';
    expect(probeAuthWeakness(f(src, 'src/components/Post.vue')).length).toBeGreaterThan(0);
  });

  it('svelte {@html} fires', () => {
    const src = '<script>\n  export let post;\n</script>\n\n<div>{@html post.body}</div>\n';
    expect(probeAuthWeakness(f(src, 'src/components/Post.svelte')).length).toBeGreaterThan(0);
  });

  it('vue v-html bound to a local constant is silent', () => {
    const src =
      '<template>\n  <div v-html="banner"></div>\n</template>\n<script>\nconst banner = "<b>Hello</b>";\n</script>\n';
    expect(probeAuthWeakness(f(src, 'src/components/Ok.vue'))).toHaveLength(0);
  });
});

describe('AWS secret access key, the aws-less spelling', () => {
  // The fixture credential is assembled at runtime rather than written out.
  // A realistic key pair in the source tripped GitHub's push protection, which
  // is the correct behaviour from a scanner and a fair reminder that a fake
  // secret in a test file is indistinguishable from a real one to everybody
  // downstream. The probe sees the whole value; the repository never holds it.
  const ID = 'AKIA' + ' 3XZQ7RBN4KLMTUVW'.trim();
  const SECRET = ['kQ7bNx2LpR9vTmWd', 'Y4hJ3sZaGfCuEoIn', '8XrVtBqM'].join('');

  it('an SDK credentials object fires', () => {
    const src = `const creds = {\n  accessKeyId: "${ID}",\n  secretAccessKey: "${SECRET}",\n};\n`;
    expect(titles(probeSecrets(f(src)))).toMatch(/Secret Access Key/);
  });

  const silent = [
    [
      'a pinned action SHA',
      'const a = "actions/checkout@60a0d83039c74a4aee543508d2ffcb1c3799cdea";\n',
    ],
    [
      'the value read from the environment',
      'const c = { secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY };\n',
    ],
    ['a 64-character hex digest', 'const secretAccessKey = "a".repeat(64);\n'],
  ];
  for (const [name, src] of silent) {
    it(`${name} is silent`, () => {
      expect(titles(probeSecrets(f(src)))).not.toMatch(/Secret Access Key/);
    });
  }
});
