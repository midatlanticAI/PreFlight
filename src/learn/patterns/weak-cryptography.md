---
title: Cryptography that runs, and does not protect
slug: weak-cryptography
type: pattern
last_updated: 2026-07-27
draft: false
related_probe_ids:
  - Weak Cryptography
sources:
  - title: OWASP Top 10 2021 A02 — Cryptographic Failures
    url: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
  - title: CWE-327 — Use of a Broken or Risky Cryptographic Algorithm
    url: https://cwe.mitre.org/data/definitions/327.html
  - title: CWE-329 — Generation of Predictable IV with CBC Mode
    url: https://cwe.mitre.org/data/definitions/329.html
  - title: CWE-916 — Use of Password Hash With Insufficient Computational Effort
    url: https://cwe.mitre.org/data/definitions/916.html
  - title: Node.js crypto — createCipheriv
    url: https://nodejs.org/api/crypto.html#cryptocreatecipherivalgorithm-key-iv-options
  - title: NIST SP 800-131A Rev. 2 — Transitioning the Use of Cryptographic Algorithms
    url: https://csrc.nist.gov/pubs/sp/800/131/a/r2/final
  - title: OWASP Password Storage Cheat Sheet
    url: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
---

Broken cryptography does not throw. The bytes come back scrambled, the tests pass, and the ciphertext looks exactly as unreadable as strong ciphertext looks. Nothing in the development loop distinguishes `aes-256-gcm` from `des-ede3`, which is why these choices survive to production so reliably.

Each shape below produces working code. The question is only what an attacker gets.

## md5 or sha1 on a credential

```js
crypto.createHash('md5').update(password).digest('hex');
```

The usual objection to md5 is collisions, and that is not the problem here. The problem is speed. A general-purpose hash is built to be fast, and an attacker holding a stolen table wants exactly that: commodity hardware works through billions of candidates a second, and the most common passwords fall in the first seconds.

sha256 is not the fix. It is also fast, and unsalted it is also vulnerable to precomputed tables.

Use a hash designed to resist the attack, with a work factor and a salt built in:

```js
await bcrypt.hash(password, 12);
await argon2.hash(password);
crypto.scryptSync(password, salt, 64);
```

Rehash on the next successful login rather than forcing a reset. The user does not need to know.

## ECB mode

```js
crypto.createCipheriv('aes-256-ecb', key, null);
```

ECB encrypts each block independently, so identical plaintext blocks produce identical ciphertext blocks. Structure survives encryption. This is the mode behind the widely reproduced image of an encrypted bitmap where the original picture is still legible, and the same leak applies to any record with repeated fields.

Use an authenticated mode, which also detects tampering:

```js
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
```

Store the IV and the auth tag alongside the ciphertext. Neither is secret.

## A cipher that is retired

```js
crypto.createCipheriv('des-ede3', key, iv);
```

DES, 3DES, RC4, RC2 and Blowfish are withdrawn or discouraged by NIST. They persist in code for the same reason they persist in tutorials: they still run. The fix is a substitution, not a redesign, and AES-256-GCM is the default worth reaching for.

## A fixed IV

```js
const IV = Buffer.from('0000000000000000', 'hex');
crypto.createCipheriv('aes-256-cbc', key, IV);
```

An initialisation vector is what makes the same plaintext encrypt differently each time. Fix it, and equal plaintexts produce equal ciphertexts under the same key, which reveals which records match without decrypting any of them. In CBC it also gives an attacker a foothold against the first block.

Generate a fresh IV per message with `crypto.randomBytes` and store it with the record. An IV is not a secret and does not need protecting, only varying.

## createCipher, the legacy one

```js
crypto.createCipher('aes-256-cbc', password);
```

The name is one character from the correct call, which is most of why it appears. It derives the key from the password with a single unsalted md5 pass and uses a zero IV. Both problems above, in one call, from an API deprecated since Node 10.

`crypto.createCipheriv` with a key from a real KDF is the replacement.

## What is not a finding

md5 and sha1 for a cache key, an ETag, a content address or a file checksum are correct, and this probe stays quiet on them. The algorithm is not the question. What the value protects is.

sha256 for a session token at rest is also fine. A 256-bit random bearer has no smaller space to search, so a slow hash buys nothing. PKCE `code_challenge` values must be sha256 by specification, and flagging those would be flatly wrong.
