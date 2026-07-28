// XL-004 / JS-TLS-VERIFY-001 positive fixture.
// Certificate verification switched off three different ways.
import https from 'node:https';
import axios from 'axios';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

export const agent = new https.Agent({ rejectUnauthorized: false });

export const client = axios.create({
  httpsAgent: new https.Agent({ rejectUnauthorized: false }),
});

export function legacyClient(request) {
  return request({ url: 'https://internal.example.com', strictSSL: false });
}

export function load(url) {
  return fetch(url, { agent: new https.Agent({ rejectUnauthorized: false }) });
}
