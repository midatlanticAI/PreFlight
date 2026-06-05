// Adversarial PRECISION tests for probeCodeCorrectness.
//
// Every test here is a "must NOT fire" case: realistic benign code where
// identifier references LOOK undeclared to a flat-allowlist checker but are
// LEGITIMATE GLOBALS in their runtime environment (service workers, web
// workers, Deno, Cloudflare Workers, modern browser APIs, Node, library
// script-tag globals, the global-directive ESLint comment, etc.) or otherwise
// legal bindings the AST walker must recognize (destructuring, params,
// labels, super, new.target, etc.).
//
// Each test asserts ZERO findings.
//
// Special focus: Category 1 (service worker globals) — the canonical
// real-world FP that drove this precision round.

import { describe, it, expect } from 'vitest';
import { probeCodeCorrectness } from '../lib/probes.js';

const file = (path, content) => ({ path, content });

// -----------------------------------------------------------------------------
// Category 1: Service worker globals
// -----------------------------------------------------------------------------
describe('precision: service worker globals', () => {
  it('sw.js with caches.open in install handler', () => {
    const src = `
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open('v1').then((cache) => cache.addAll(['/', '/index.html']))
  );
  self.skipWaiting();
});
`;
    expect(probeCodeCorrectness([file('public/sw.js', src)])).toEqual([]);
  });

  it('service-worker.js with clients.claim on activate', () => {
    const src = `
self.addEventListener('activate', (event) => {
  event.waitUntil(clients.claim());
});
`;
    expect(probeCodeCorrectness([file('public/service-worker.js', src)])).toEqual([]);
  });

  it('content-detected service worker (not sw.js name) using caches', () => {
    const src = `
self.addEventListener('install', (event) => {
  event.waitUntil(caches.open('static-v2').then((c) => c.add('/app.js')));
});

self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request).then((hit) => hit || fetch(event.request))
  );
});
`;
    expect(probeCodeCorrectness([file('src/worker/offline.js', src)])).toEqual([]);
  });

  it('sw.js with registration.showNotification', () => {
    const src = `
self.addEventListener('push', (event) => {
  const data = event.data ? event.data.json() : {};
  event.waitUntil(
    registration.showNotification(data.title || 'New message', {
      body: data.body || '',
    })
  );
});
`;
    expect(probeCodeCorrectness([file('sw.js', src)])).toEqual([]);
  });

  it('sw.js cache-first strategy with FetchEvent typing', () => {
    const src = `
const CACHE = 'shell-v3';

self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) return cached;
      return fetch(event.request).then((resp) => {
        const copy = resp.clone();
        caches.open(CACHE).then((cache) => cache.put(event.request, copy));
        return resp;
      });
    })
  );
});
`;
    expect(probeCodeCorrectness([file('public/sw.js', src)])).toEqual([]);
  });

  it('service-worker.js skipWaiting + clients.claim combo', () => {
    const src = `
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(clients.claim()));
`;
    expect(probeCodeCorrectness([file('service-worker.js', src)])).toEqual([]);
  });

  it('sw.js using CacheStorage / Cache constructor reference', () => {
    const src = `
async function purge() {
  const keys = await caches.keys();
  await Promise.all(keys.map((k) => caches.delete(k)));
}

self.addEventListener('message', (event) => {
  if (event.data === 'purge') event.waitUntil(purge());
});
`;
    expect(probeCodeCorrectness([file('public/sw.js', src)])).toEqual([]);
  });

  it('service worker with broadcast to clients.matchAll', () => {
    const src = `
self.addEventListener('activate', (event) => {
  event.waitUntil(
    clients.matchAll({ type: 'window' }).then((all) => {
      all.forEach((c) => c.postMessage({ type: 'activated' }));
    })
  );
});
`;
    expect(probeCodeCorrectness([file('src/sw/index.js', src)])).toEqual([]);
  });

  it('sw.js using ExtendableEvent.waitUntil pattern', () => {
    const src = `
self.addEventListener('sync', (event) => {
  if (event.tag === 'flush-queue') {
    event.waitUntil(flushQueue());
  }
});

async function flushQueue() {
  const cache = await caches.open('outbox');
  // ...
  return cache;
}
`;
    expect(probeCodeCorrectness([file('public/sw.js', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 2: Web Worker globals
// -----------------------------------------------------------------------------
describe('precision: web worker globals', () => {
  it('worker.js postMessage / onmessage', () => {
    const src = `
onmessage = (e) => {
  const result = e.data * 2;
  postMessage(result);
};
`;
    expect(probeCodeCorrectness([file('src/workers/double.worker.js', src)])).toEqual([]);
  });

  it('worker using importScripts', () => {
    const src = `
importScripts('./helper.js', './shared.js');

self.onmessage = (e) => {
  postMessage({ ok: true, payload: e.data });
};
`;
    expect(probeCodeCorrectness([file('public/workers/main.js', src)])).toEqual([]);
  });

  it('main thread spawning a Worker', () => {
    const src = `
const w = new Worker('/workers/heavy.js', { type: 'module' });
w.postMessage({ start: true });
w.onmessage = (e) => console.log('worker said', e.data);
`;
    expect(probeCodeCorrectness([file('src/spawn.js', src)])).toEqual([]);
  });

  it('SharedWorker / DedicatedWorker references', () => {
    const src = `
const shared = new SharedWorker('/shared.js');
shared.port.postMessage('hello');
shared.port.onmessage = (e) => console.log(e.data);
`;
    expect(probeCodeCorrectness([file('src/shared-client.js', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 3: Deno globals
// -----------------------------------------------------------------------------
describe('precision: Deno globals', () => {
  it('Deno.serve top-level', () => {
    const src = `
Deno.serve({ port: 8000 }, (req) => new Response('hello ' + req.url));
`;
    expect(probeCodeCorrectness([file('server.js', src)])).toEqual([]);
  });

  it('Deno.env.get for secrets', () => {
    const src = `
const apiKey = Deno.env.get('API_KEY');
if (!apiKey) {
  console.error('missing API_KEY');
}
export { apiKey };
`;
    expect(probeCodeCorrectness([file('src/config.js', src)])).toEqual([]);
  });

  it('Deno.readFile for static content', () => {
    const src = `
async function loadConfig(path) {
  const bytes = await Deno.readFile(path);
  return new TextDecoder().decode(bytes);
}

export { loadConfig };
`;
    expect(probeCodeCorrectness([file('src/loader.js', src)])).toEqual([]);
  });

  it('Deno test runner shape', () => {
    const src = `
Deno.test('adds correctly', () => {
  if (1 + 1 !== 2) throw new Error('math broken');
});
`;
    expect(probeCodeCorrectness([file('src/math.test.js', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 4: Cloudflare Workers globals
// -----------------------------------------------------------------------------
describe('precision: Cloudflare Workers globals', () => {
  it('module-style worker default export', () => {
    const src = `
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/health') return new Response('ok');
    return new Response('not found', { status: 404 });
  },
};
`;
    expect(probeCodeCorrectness([file('worker/index.js', src)])).toEqual([]);
  });

  it('worker using caches and Headers', () => {
    const src = `
export default {
  async fetch(request) {
    const cache = caches.default;
    const cached = await cache.match(request);
    if (cached) return cached;
    const resp = new Response('fresh', {
      headers: new Headers({ 'cache-control': 'public, max-age=60' }),
    });
    return resp;
  },
};
`;
    expect(probeCodeCorrectness([file('worker/cache.js', src)])).toEqual([]);
  });

  it('worker with crypto.subtle for HMAC', () => {
    const src = `
export default {
  async fetch(request, env) {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      enc.encode(env.SECRET),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', key, enc.encode('payload'));
    return new Response(new Uint8Array(sig));
  },
};
`;
    expect(probeCodeCorrectness([file('worker/sign.js', src)])).toEqual([]);
  });

  it('legacy service-worker style addEventListener fetch', () => {
    const src = `
addEventListener('fetch', (event) => {
  event.respondWith(
    fetch(event.request).catch(() => new Response('upstream down', { status: 502 }))
  );
});
`;
    expect(probeCodeCorrectness([file('worker/legacy.js', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 5: Browser globals the allowlist may miss
// -----------------------------------------------------------------------------
describe('precision: modern browser globals', () => {
  it('crypto.subtle digest', () => {
    const src = `
async function sha256(text) {
  const buf = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
export { sha256 };
`;
    expect(probeCodeCorrectness([file('src/hash.js', src)])).toEqual([]);
  });

  it('requestAnimationFrame loop', () => {
    const src = `
function tick(t) {
  // ...
  requestAnimationFrame(tick);
}
requestAnimationFrame(tick);
`;
    expect(probeCodeCorrectness([file('src/raf.js', src)])).toEqual([]);
  });

  it('queueMicrotask and structuredClone', () => {
    const src = `
function defer(cb) {
  queueMicrotask(cb);
}

function deepCopy(o) {
  return structuredClone(o);
}

export { defer, deepCopy };
`;
    expect(probeCodeCorrectness([file('src/util.js', src)])).toEqual([]);
  });

  it('BroadcastChannel + MessageChannel', () => {
    const src = `
const bus = new BroadcastChannel('app');
bus.postMessage({ type: 'hello' });

const ch = new MessageChannel();
ch.port1.onmessage = (e) => console.log(e.data);
ch.port2.postMessage('ping');
`;
    expect(probeCodeCorrectness([file('src/channels.js', src)])).toEqual([]);
  });

  it('performance.now timing', () => {
    const src = `
function time(label, fn) {
  const t0 = performance.now();
  const out = fn();
  const t1 = performance.now();
  console.log(label, t1 - t0);
  return out;
}
export { time };
`;
    expect(probeCodeCorrectness([file('src/perf.js', src)])).toEqual([]);
  });

  it('atob / btoa base64 round-trip', () => {
    const src = `
function encode(s) { return btoa(s); }
function decode(s) { return atob(s); }
export { encode, decode };
`;
    expect(probeCodeCorrectness([file('src/b64.js', src)])).toEqual([]);
  });

  it('Intl.DateTimeFormat', () => {
    const src = `
const fmt = new Intl.DateTimeFormat('en-US', { dateStyle: 'medium' });
export const today = () => fmt.format(new Date());
`;
    expect(probeCodeCorrectness([file('src/locale.js', src)])).toEqual([]);
  });

  it('BigInt literal-style construction', () => {
    const src = `
const big = BigInt('9007199254740993');
export { big };
`;
    expect(probeCodeCorrectness([file('src/big.js', src)])).toEqual([]);
  });

  it('WebAssembly.instantiateStreaming', () => {
    const src = `
async function loadWasm(url) {
  const mod = await WebAssembly.instantiateStreaming(fetch(url), {});
  return mod.instance.exports;
}
export { loadWasm };
`;
    expect(probeCodeCorrectness([file('src/wasm.js', src)])).toEqual([]);
  });

  it('customElements.define', () => {
    const src = `
class MyEl extends HTMLElement {
  connectedCallback() {
    this.textContent = 'hi';
  }
}
customElements.define('my-el', MyEl);
`;
    expect(probeCodeCorrectness([file('src/ce.js', src)])).toEqual([]);
  });

  it('matchMedia + getComputedStyle', () => {
    const src = `
const dark = matchMedia('(prefers-color-scheme: dark)').matches;
const root = document.documentElement;
const cs = getComputedStyle(root);
console.log(dark, cs.fontSize);
`;
    expect(probeCodeCorrectness([file('src/style.js', src)])).toEqual([]);
  });

  it('OffscreenCanvas + ImageBitmap', () => {
    const src = `
async function paint(blob) {
  const bmp = await createImageBitmap(blob);
  const canvas = new OffscreenCanvas(bmp.width, bmp.height);
  const ctx = canvas.getContext('2d');
  ctx.drawImage(bmp, 0, 0);
  return canvas.transferToImageBitmap();
}
export { paint };
`;
    expect(probeCodeCorrectness([file('src/paint.js', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 6: Node globals the allowlist may miss
// -----------------------------------------------------------------------------
describe('precision: Node globals', () => {
  it('setTimeout / clearTimeout in Node-ish module', () => {
    const src = `
function debounce(fn, ms) {
  let id;
  return (...args) => {
    clearTimeout(id);
    id = setTimeout(() => fn(...args), ms);
  };
}
module.exports = { debounce };
`;
    expect(probeCodeCorrectness([file('lib/debounce.cjs', src)])).toEqual([]);
  });

  it('setInterval / clearInterval poller', () => {
    const src = `
function poll(fn, ms) {
  const id = setInterval(fn, ms);
  return () => clearInterval(id);
}
module.exports = poll;
`;
    expect(probeCodeCorrectness([file('lib/poll.cjs', src)])).toEqual([]);
  });

  it('URL + URLSearchParams in Node script', () => {
    const src = `
function parse(href) {
  const u = new URL(href);
  const params = new URLSearchParams(u.search);
  return Object.fromEntries(params);
}
module.exports = parse;
`;
    expect(probeCodeCorrectness([file('scripts/parse-url.cjs', src)])).toEqual([]);
  });

  it('TextEncoder / TextDecoder in Node script', () => {
    const src = `
const enc = new TextEncoder();
const dec = new TextDecoder();
function roundtrip(s) {
  return dec.decode(enc.encode(s));
}
module.exports = roundtrip;
`;
    expect(probeCodeCorrectness([file('scripts/text.cjs', src)])).toEqual([]);
  });

  it('process.env / process.argv / process.cwd', () => {
    const src = `
const mode = process.env.NODE_ENV || 'development';
const args = process.argv.slice(2);
const here = process.cwd();
console.log(mode, args, here);
`;
    expect(probeCodeCorrectness([file('scripts/run.mjs', src)])).toEqual([]);
  });

  it('Buffer global in Node', () => {
    const src = `
function toHex(s) {
  return Buffer.from(s, 'utf8').toString('hex');
}
module.exports = toHex;
`;
    expect(probeCodeCorrectness([file('lib/hex.cjs', src)])).toEqual([]);
  });

  it('__dirname / __filename in CommonJS', () => {
    const src = `
const path = require('path');
const here = path.dirname(__filename);
console.log(here, __dirname);
`;
    expect(probeCodeCorrectness([file('lib/where.cjs', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 7: Recent web standards
// -----------------------------------------------------------------------------
describe('precision: recent web standards', () => {
  it('Notification permission request', () => {
    const src = `
async function ask() {
  if (Notification.permission === 'default') {
    return Notification.requestPermission();
  }
  return Notification.permission;
}
export { ask };
`;
    expect(probeCodeCorrectness([file('src/notify.js', src)])).toEqual([]);
  });

  it('navigator.clipboard + ClipboardItem', () => {
    const src = `
async function copyImage(blob) {
  const item = new ClipboardItem({ [blob.type]: blob });
  await navigator.clipboard.write([item]);
}
export { copyImage };
`;
    expect(probeCodeCorrectness([file('src/clip.js', src)])).toEqual([]);
  });

  it('WebSocket client', () => {
    const src = `
const ws = new WebSocket('wss://example.com/socket');
ws.addEventListener('message', (e) => console.log(e.data));
ws.addEventListener('open', () => ws.send('hello'));
`;
    expect(probeCodeCorrectness([file('src/ws.js', src)])).toEqual([]);
  });

  it('EventSource for SSE', () => {
    const src = `
const es = new EventSource('/events');
es.onmessage = (e) => console.log(e.data);
es.onerror = () => es.close();
`;
    expect(probeCodeCorrectness([file('src/sse.js', src)])).toEqual([]);
  });

  it('MediaRecorder + getUserMedia', () => {
    const src = `
async function record() {
  const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
  const rec = new MediaRecorder(stream);
  rec.start();
  return rec;
}
export { record };
`;
    expect(probeCodeCorrectness([file('src/record.js', src)])).toEqual([]);
  });

  it('RTCPeerConnection setup', () => {
    const src = `
function makePeer() {
  const pc = new RTCPeerConnection({ iceServers: [] });
  pc.addEventListener('icecandidate', (e) => console.log(e.candidate));
  return pc;
}
export { makePeer };
`;
    expect(probeCodeCorrectness([file('src/rtc.js', src)])).toEqual([]);
  });

  it('navigator.permissions.query', () => {
    const src = `
async function geoState() {
  const status = await navigator.permissions.query({ name: 'geolocation' });
  return status.state;
}
export { geoState };
`;
    expect(probeCodeCorrectness([file('src/perm.js', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 8: Script-tag library globals (declared via /* global */ directive)
// -----------------------------------------------------------------------------
describe('precision: script-tag library globals', () => {
  it('jQuery $ via global directive', () => {
    const src = `
/* global $ */
$(document).ready(() => {
  $('.btn').on('click', () => alert('hi'));
});
`;
    expect(probeCodeCorrectness([file('public/legacy.js', src)])).toEqual([]);
  });

  it('lodash _ via global directive', () => {
    const src = `
/* global _ */
const grouped = _.groupBy([1, 2, 3, 4], (n) => n % 2);
console.log(grouped);
`;
    expect(probeCodeCorrectness([file('public/group.js', src)])).toEqual([]);
  });

  it('Stripe.js via global directive', () => {
    const src = `
/* global Stripe */
const stripe = Stripe('pk_test_123');
const elements = stripe.elements();
const card = elements.create('card');
card.mount('#card');
`;
    expect(probeCodeCorrectness([file('public/checkout.js', src)])).toEqual([]);
  });

  it('gtag analytics via global directive', () => {
    const src = `
/* global gtag, dataLayer */
dataLayer.push({ event: 'page_view' });
gtag('event', 'cta_click', { label: 'hero' });
`;
    expect(probeCodeCorrectness([file('public/analytics.js', src)])).toEqual([]);
  });

  it('d3 via global directive', () => {
    const src = `
/* global d3 */
const svg = d3.select('#chart').append('svg').attr('width', 400).attr('height', 200);
svg.append('circle').attr('cx', 200).attr('cy', 100).attr('r', 40);
`;
    expect(probeCodeCorrectness([file('public/chart.js', src)])).toEqual([]);
  });

  it('multiple library globals on one directive line', () => {
    const src = `
/* global jQuery, lodash, Sentry */
jQuery.noConflict();
const arr = lodash.range(5);
Sentry.captureMessage('loaded ' + arr.length);
`;
    expect(probeCodeCorrectness([file('public/bundle.js', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 9: /* global X */ directive (general form)
// -----------------------------------------------------------------------------
describe('precision: /* global X */ directive honoring', () => {
  it('custom runtime-injected global', () => {
    const src = `
/* global MY_INJECTED_CONFIG */
function getRegion() {
  return MY_INJECTED_CONFIG.region;
}
export { getRegion };
`;
    expect(probeCodeCorrectness([file('src/region.js', src)])).toEqual([]);
  });

  it('multiple custom globals', () => {
    const src = `
/* global APP_VERSION, BUILD_HASH, FEATURE_FLAGS */
console.log('app', APP_VERSION, BUILD_HASH);
if (FEATURE_FLAGS.experimentX) console.log('exp on');
`;
    expect(probeCodeCorrectness([file('src/banner.js', src)])).toEqual([]);
  });

  it('globals directive with writable: true syntax', () => {
    const src = `
/* global MY_COUNTER:writable */
MY_COUNTER = (MY_COUNTER || 0) + 1;
console.log(MY_COUNTER);
`;
    expect(probeCodeCorrectness([file('src/counter.js', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 10: Destructuring with default values
// -----------------------------------------------------------------------------
describe('precision: destructuring with defaults', () => {
  it('object destructuring with default value', () => {
    const DEFAULT_TIMEOUT = 1000;
    void DEFAULT_TIMEOUT;
    const src = `
const DEFAULT_TIMEOUT = 1000;

function makeClient(opts) {
  const { timeout = DEFAULT_TIMEOUT, retries = 3 } = opts || {};
  return { timeout, retries };
}
export { makeClient };
`;
    expect(probeCodeCorrectness([file('src/client.js', src)])).toEqual([]);
  });

  it('nested destructuring with defaults', () => {
    const src = `
const FALLBACK = { region: 'us-east-1' };

function parse(cfg) {
  const { service: { region = FALLBACK.region } = {} } = cfg;
  return region;
}
export { parse };
`;
    expect(probeCodeCorrectness([file('src/cfg.js', src)])).toEqual([]);
  });

  it('array destructuring with defaults', () => {
    const src = `
const ZERO = 0;
const [first = ZERO, second = ZERO] = [];
console.log(first, second);
`;
    expect(probeCodeCorrectness([file('src/arr.js', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 11: Destructuring with renames
// -----------------------------------------------------------------------------
describe('precision: destructuring with renames', () => {
  it('object destructuring rename', () => {
    const src = `
function getName(obj) {
  const { firstName: f, lastName: l } = obj;
  return f + ' ' + l;
}
export { getName };
`;
    expect(probeCodeCorrectness([file('src/name.js', src)])).toEqual([]);
  });

  it('rename + default together', () => {
    const src = `
const DEFAULT_HOST = 'localhost';
function connect(opts) {
  const { host: h = DEFAULT_HOST, port: p = 5432 } = opts || {};
  return h + ':' + p;
}
export { connect };
`;
    expect(probeCodeCorrectness([file('src/conn.js', src)])).toEqual([]);
  });

  it('nested rename', () => {
    const src = `
function inner(o) {
  const { meta: { id: metaId, type: metaType } } = o;
  return metaId + '/' + metaType;
}
export { inner };
`;
    expect(probeCodeCorrectness([file('src/meta.js', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 12: Higher-order callbacks with param scope
// -----------------------------------------------------------------------------
describe('precision: higher-order param scope', () => {
  it('map / filter / reduce chain', () => {
    const src = `
function pipeline(arr) {
  return arr
    .filter((n) => n > 0)
    .map((n) => n * 2)
    .reduce((acc, n) => acc + n, 0);
}
export { pipeline };
`;
    expect(probeCodeCorrectness([file('src/pipe.js', src)])).toEqual([]);
  });

  it('nested arrow scopes', () => {
    const src = `
const compose = (f) => (g) => (x) => f(g(x));
const addOne = (n) => n + 1;
const double = (n) => n * 2;
const both = compose(addOne)(double);
console.log(both(3));
`;
    expect(probeCodeCorrectness([file('src/compose.js', src)])).toEqual([]);
  });

  it('forEach with index param', () => {
    const src = `
function dump(arr) {
  arr.forEach((item, i, all) => {
    console.log(i, '/', all.length, '=', item);
  });
}
export { dump };
`;
    expect(probeCodeCorrectness([file('src/dump.js', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 13: Async function declarations + async arrows
// -----------------------------------------------------------------------------
describe('precision: async declarations', () => {
  it('async function declaration is bound', () => {
    const src = `
async function fetchJson(url) {
  const r = await fetch(url);
  return r.json();
}

export default fetchJson;
`;
    expect(probeCodeCorrectness([file('src/fetch-json.js', src)])).toEqual([]);
  });

  it('async arrow assigned to const', () => {
    const src = `
const loadAll = async (urls) => Promise.all(urls.map((u) => fetch(u)));
export { loadAll };
`;
    expect(probeCodeCorrectness([file('src/load.js', src)])).toEqual([]);
  });

  it('async generator', () => {
    const src = `
async function* pages(url) {
  let next = url;
  while (next) {
    const r = await fetch(next);
    const data = await r.json();
    yield data.items;
    next = data.next;
  }
}
export { pages };
`;
    expect(probeCodeCorrectness([file('src/pages.js', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 14: Classes with method bodies, `this` inside
// -----------------------------------------------------------------------------
describe('precision: classes and `this`', () => {
  it('basic class with methods uses `this`', () => {
    const src = `
class Counter {
  constructor(start = 0) {
    this.n = start;
  }
  inc() {
    this.n += 1;
    return this.n;
  }
  reset() {
    this.n = 0;
  }
}
export { Counter };
`;
    expect(probeCodeCorrectness([file('src/counter-class.js', src)])).toEqual([]);
  });

  it('class with static + private-ish field', () => {
    const src = `
class Registry {
  static instances = 0;
  constructor(name) {
    this.name = name;
    Registry.instances += 1;
  }
}
export { Registry };
`;
    expect(probeCodeCorrectness([file('src/registry.js', src)])).toEqual([]);
  });

  it('class extends with method chain', () => {
    const src = `
class Animal {
  speak() { return 'noise'; }
}
class Dog extends Animal {
  speak() { return 'bark'; }
}
const d = new Dog();
console.log(d.speak());
`;
    expect(probeCodeCorrectness([file('src/dog.js', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 15: Getters/setters and computed property keys
// -----------------------------------------------------------------------------
describe('precision: getters/setters/computed keys', () => {
  it('getter/setter on object literal', () => {
    const src = `
const obj = {
  _v: 0,
  get v() { return this._v; },
  set v(n) { this._v = n; },
};
obj.v = 5;
console.log(obj.v);
`;
    expect(probeCodeCorrectness([file('src/access.js', src)])).toEqual([]);
  });

  it('computed property key uses outer binding', () => {
    const src = `
const key = 'dynamic';
const obj = {
  [key]: 42,
  ['static_' + key]: 1,
};
console.log(obj.dynamic);
`;
    expect(probeCodeCorrectness([file('src/computed.js', src)])).toEqual([]);
  });

  it('class with getter/setter', () => {
    const src = `
class Temp {
  constructor(c) { this._c = c; }
  get celsius() { return this._c; }
  set celsius(c) { this._c = c; }
  get fahrenheit() { return this._c * 9/5 + 32; }
}
export { Temp };
`;
    expect(probeCodeCorrectness([file('src/temp.js', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 16: TypeScript files should be skipped entirely
// -----------------------------------------------------------------------------
describe('precision: TypeScript files are skipped', () => {
  it('.ts file with types and decorators yields zero findings', () => {
    const src = `
interface User { id: string; name: string; }
const u: User = { id: 'a', name: 'b' };
function greet(user: User): string {
  return 'hello ' + user.name;
}
console.log(greet(u));
`;
    expect(probeCodeCorrectness([file('src/user.ts', src)])).toEqual([]);
  });

  it('.tsx file with React + types yields zero findings', () => {
    const src = `
type Props = { label: string };
const Btn: React.FC<Props> = ({ label }) => <button>{label}</button>;
export default Btn;
`;
    expect(probeCodeCorrectness([file('src/Btn.tsx', src)])).toEqual([]);
  });

  it('.ts with generics and intentionally undeclared-looking refs', () => {
    const src = `
function identity<T>(x: T): T { return x; }
type Result<T> = { ok: true; value: T } | { ok: false; error: SomeUndeclaredType };
const r = identity<number>(1);
console.log(r);
`;
    expect(probeCodeCorrectness([file('src/id.ts', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 17: JSX intrinsic elements
// -----------------------------------------------------------------------------
describe('precision: JSX intrinsics are not identifier refs', () => {
  it('div / span / button intrinsics', () => {
    const src = `
import React from 'react';
function Card({ title }) {
  return (
    <div>
      <span>{title}</span>
      <button>OK</button>
    </div>
  );
}
export default Card;
`;
    expect(probeCodeCorrectness([file('src/Card.jsx', src)])).toEqual([]);
  });

  it('form / input / label intrinsics with attrs', () => {
    const src = `
import React from 'react';
function Field({ name, label }) {
  return (
    <label>
      {label}
      <input type="text" name={name} />
    </label>
  );
}
export default Field;
`;
    expect(probeCodeCorrectness([file('src/Field.jsx', src)])).toEqual([]);
  });

  it('lowercase SVG intrinsics', () => {
    const src = `
import React from 'react';
function Dot() {
  return (
    <svg viewBox="0 0 10 10">
      <circle cx="5" cy="5" r="4" />
    </svg>
  );
}
export default Dot;
`;
    expect(probeCodeCorrectness([file('src/Dot.jsx', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 18: JSX with hyphenated custom-element names
// -----------------------------------------------------------------------------
describe('precision: hyphenated JSX names', () => {
  it('custom-element style hyphenated tag', () => {
    const src = `
import React from 'react';
function Wrap() {
  return <my-widget data-id="x"><span>inner</span></my-widget>;
}
export default Wrap;
`;
    expect(probeCodeCorrectness([file('src/Wrap.jsx', src)])).toEqual([]);
  });

  it('nested hyphenated tags', () => {
    const src = `
import React from 'react';
function Panel() {
  return (
    <app-shell>
      <app-header />
      <app-main><app-card /></app-main>
    </app-shell>
  );
}
export default Panel;
`;
    expect(probeCodeCorrectness([file('src/Panel.jsx', src)])).toEqual([]);
  });

  it('hyphenated tag with attribute expression', () => {
    const src = `
import React from 'react';
function Banner({ label }) {
  return <fancy-banner aria-label={label}>{label}</fancy-banner>;
}
export default Banner;
`;
    expect(probeCodeCorrectness([file('src/Banner.jsx', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 19: Rest params + spread
// -----------------------------------------------------------------------------
describe('precision: rest params', () => {
  it('function rest param `...rest`', () => {
    const src = `
function tail(first, ...rest) {
  console.log(first);
  return rest;
}
export { tail };
`;
    expect(probeCodeCorrectness([file('src/tail.js', src)])).toEqual([]);
  });

  it('rest in array destructuring', () => {
    const src = `
const [head, ...everythingElse] = [1, 2, 3, 4];
console.log(head, everythingElse);
`;
    expect(probeCodeCorrectness([file('src/restarr.js', src)])).toEqual([]);
  });

  it('rest in object destructuring', () => {
    const src = `
function strip(obj) {
  const { secret, ...safe } = obj;
  void secret;
  return safe;
}
export { strip };
`;
    expect(probeCodeCorrectness([file('src/strip.js', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 20: `arguments` inside non-arrow functions
// -----------------------------------------------------------------------------
describe('precision: `arguments` is function-local', () => {
  it('arguments inside function declaration', () => {
    const src = `
function variadic() {
  let total = 0;
  for (let i = 0; i < arguments.length; i++) total += arguments[i];
  return total;
}
export { variadic };
`;
    expect(probeCodeCorrectness([file('src/variadic.js', src)])).toEqual([]);
  });

  it('arguments inside function expression', () => {
    const src = `
const log = function () {
  console.log('count', arguments.length);
};
export { log };
`;
    expect(probeCodeCorrectness([file('src/log.js', src)])).toEqual([]);
  });

  it('arguments inside class method', () => {
    const src = `
class Sink {
  push() {
    return Array.from(arguments);
  }
}
export { Sink };
`;
    expect(probeCodeCorrectness([file('src/sink.js', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 21: Labeled statements
// -----------------------------------------------------------------------------
describe('precision: labels are not identifier refs', () => {
  it('break to outer label', () => {
    const src = `
function find(grid, target) {
  outer: for (let i = 0; i < grid.length; i++) {
    for (let j = 0; j < grid[i].length; j++) {
      if (grid[i][j] === target) break outer;
    }
  }
}
export { find };
`;
    expect(probeCodeCorrectness([file('src/find.js', src)])).toEqual([]);
  });

  it('continue to outer label', () => {
    const src = `
function process(items) {
  loop: for (const item of items) {
    if (!item) continue loop;
    console.log(item);
  }
}
export { process };
`;
    expect(probeCodeCorrectness([file('src/process.js', src)])).toEqual([]);
  });

  it('nested labels', () => {
    const src = `
function brute() {
  a: for (let i = 0; i < 3; i++) {
    b: for (let j = 0; j < 3; j++) {
      if (i + j > 3) break a;
      if (j === 2) continue b;
    }
  }
}
export { brute };
`;
    expect(probeCodeCorrectness([file('src/brute.js', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 22: `new.target` MetaProperty
// -----------------------------------------------------------------------------
describe('precision: new.target', () => {
  it('class constructor with new.target check', () => {
    const src = `
class Foo {
  constructor() {
    if (new.target !== Foo) throw new Error('subclass only');
  }
}
export { Foo };
`;
    expect(probeCodeCorrectness([file('src/foo.js', src)])).toEqual([]);
  });

  it('function with new.target guard', () => {
    const src = `
function MustBeNew() {
  if (!new.target) throw new TypeError('call with new');
  this.ok = true;
}
export { MustBeNew };
`;
    expect(probeCodeCorrectness([file('src/mustbenew.js', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 23: Dynamic import()
// -----------------------------------------------------------------------------
describe('precision: dynamic import()', () => {
  it('await import top-level in module', () => {
    const src = `
const heavy = await import('./heavy.js');
heavy.run();
`;
    expect(probeCodeCorrectness([file('src/loader.mjs', src)])).toEqual([]);
  });

  it('lazy import inside async function', () => {
    const src = `
async function lazy(name) {
  const mod = await import('./plugins/' + name + '.js');
  return mod.default;
}
export { lazy };
`;
    expect(probeCodeCorrectness([file('src/lazy.js', src)])).toEqual([]);
  });

  it('import.meta.url', () => {
    const src = `
const here = new URL('.', import.meta.url);
console.log(here.href);
`;
    expect(probeCodeCorrectness([file('src/meta-url.mjs', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 24: `super` in class methods
// -----------------------------------------------------------------------------
describe('precision: super in subclasses', () => {
  it('super.method() call in subclass', () => {
    const src = `
class A {
  greet() { return 'A'; }
}
class B extends A {
  greet() { return super.greet() + 'B'; }
}
console.log(new B().greet());
`;
    expect(probeCodeCorrectness([file('src/ab.js', src)])).toEqual([]);
  });

  it('super(...args) in derived constructor', () => {
    const src = `
class Base {
  constructor(x) { this.x = x; }
}
class Sub extends Base {
  constructor(x, y) {
    super(x);
    this.y = y;
  }
}
export { Sub };
`;
    expect(probeCodeCorrectness([file('src/sub.js', src)])).toEqual([]);
  });

  it('super in object method shorthand', () => {
    const src = `
const proto = {
  greet() { return 'proto'; },
};
const obj = {
  __proto__: proto,
  greet() { return super.greet() + '!'; },
};
console.log(obj.greet());
`;
    expect(probeCodeCorrectness([file('src/super-obj.js', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 25: Decorators in .js (experimental, but legal)
// -----------------------------------------------------------------------------
describe('precision: decorators in .js (experimental)', () => {
  // Note: acorn-stage-3-decorators / proposal support varies. If the parser
  // bails, these probably fall through cleanly with no findings.
  it('class with @decorator annotation', () => {
    const src = `
function readonly(target, key, desc) {
  desc.writable = false;
  return desc;
}

class Config {
  @readonly
  version() { return 1; }
}
export { Config };
`;
    expect(probeCodeCorrectness([file('src/config-decorated.js', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Category 26: Top-level await
// -----------------------------------------------------------------------------
describe('precision: top-level await in modules', () => {
  it('module-level await fetch', () => {
    const src = `
const res = await fetch('/api/config');
const cfg = await res.json();
export { cfg };
`;
    expect(probeCodeCorrectness([file('src/tla.mjs', src)])).toEqual([]);
  });

  it('module-level await import', () => {
    const src = `
const { default: handler } = await import('./handler.js');
handler();
`;
    expect(probeCodeCorrectness([file('src/tla-import.mjs', src)])).toEqual([]);
  });

  it('top-level await in for-await-of', () => {
    const src = `
async function* stream() {
  yield 1; yield 2; yield 3;
}
for await (const n of stream()) {
  console.log(n);
}
`;
    expect(probeCodeCorrectness([file('src/tla-stream.mjs', src)])).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Edge cases (ambiguous, called out as such)
// -----------------------------------------------------------------------------
describe('precision: edge cases', () => {
  // Ambiguous: HTMLElement is a browser global the allowlist should cover, but
  // some allowlists miss it. This is benign in any browser context.
  it('HTMLElement subclass for custom element', () => {
    const src = `
class Card extends HTMLElement {
  connectedCallback() {
    this.innerHTML = '<p>card</p>';
  }
}
customElements.define('x-card', Card);
`;
    expect(probeCodeCorrectness([file('src/x-card.js', src)])).toEqual([]);
  });

  // Ambiguous: `globalThis` is a standard ES2020 binding; allowlist should
  // include it.
  it('globalThis cross-realm probe', () => {
    const src = `
const root = globalThis;
console.log(typeof root.fetch);
`;
    expect(probeCodeCorrectness([file('src/global-this.js', src)])).toEqual([]);
  });

  // Ambiguous: tagged template `String.raw` is a static method ref; legal.
  it('String.raw tagged template', () => {
    const src = `
const path = String.raw\`C:\\Users\\me\\file.txt\`;
console.log(path);
`;
    expect(probeCodeCorrectness([file('src/raw.js', src)])).toEqual([]);
  });

  // Ambiguous: `Symbol.iterator` access on a value -- Symbol is global.
  it('Symbol.iterator on iterable', () => {
    const src = `
function isIterable(v) {
  return v != null && typeof v[Symbol.iterator] === 'function';
}
export { isIterable };
`;
    expect(probeCodeCorrectness([file('src/iter.js', src)])).toEqual([]);
  });

  // Ambiguous: Reflect / Proxy globals.
  it('Reflect + Proxy interceptors', () => {
    const src = `
function wrap(target) {
  return new Proxy(target, {
    get(t, k, r) { return Reflect.get(t, k, r); },
  });
}
export { wrap };
`;
    expect(probeCodeCorrectness([file('src/wrap.js', src)])).toEqual([]);
  });
});
