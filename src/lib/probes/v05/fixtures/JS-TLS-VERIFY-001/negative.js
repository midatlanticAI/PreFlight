// XL-004 / JS-TLS-VERIFY-001 negative fixture.
// Verification stays on; the private CA is supplied instead of removed.
import fs from 'node:fs';
import https from 'node:https';

export const agent = new https.Agent({
  ca: fs.readFileSync('/etc/ssl/corp-ca.pem'),
  rejectUnauthorized: true,
});

export const defaultAgent = new https.Agent();

export function load(url) {
  return fetch(url, { agent });
}
