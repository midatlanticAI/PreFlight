// Per-await rejection guarding.
//
// Reported by an operator running PreFlight against their own cockpit, 2026-07:
// the probe correctly flagged one unguarded logout handler and missed the
// password handler four lines below it, which has the identical defect.
//
//   $('pwSave').addEventListener('click', async () => {
//     const r = await fetch('/api/auth/password', { method: 'POST' });
//     const j = await r.json().catch(() => ({}));
//     $('pwMsg').textContent = r.ok ? 'password changed' : j.error;
//   });
//
// The `.catch` is on `r.json()`. If the fetch itself rejects, the listener
// rejects with no handler, `pwMsg` never updates, and the user clicks Save to
// no visible effect. The check was asking whether the body contained `.catch(`
// anywhere, which cannot tell a handler on one promise from a handler on
// another. `try {` had the same defect.
//
// The rule is now per-await: an await is guarded when it sits inside a try
// statement, or when the awaited expression itself carries `.catch(…)` at its
// own top level. Anything else is exposed.
//
// Corpus check for this change: 2 findings on the reporting project (both
// real), 10 across 2,270 files of a large CLI fork, 0 on PreFlight's own tree.

import { describe, it, expect } from 'vitest';
import { probeCodeQuality } from '../lib/probes/quality.js';

const TITLE = 'async callback in fire-and-forget position';
const run = (content, path = 'src/a.js') =>
  probeCodeQuality([{ path, content }]).filter((f) => f.title.includes(TITLE));
const fires = (content) => expect(run(content).length).toBeGreaterThan(0);
const quiet = (content) => expect(run(content)).toEqual([]);

describe('a .catch on one promise does not guard another', () => {
  it('fires on the reported handler: catch is on r.json(), not the fetch', () => {
    fires(`
$('pwSave').addEventListener('click', async () => {
  const r = await fetch('/api/auth/password', { method: 'POST' });
  const j = await r.json().catch(() => ({}));
  $('pwMsg').textContent = r.ok ? 'password changed' : j.error;
});`);
  });

  it('fires when a .catch sits on an inner call rather than the awaited one', () => {
    // The handler belongs to load(). send() can still reject.
    fires(`
btn.addEventListener('click', async () => {
  await send(load().catch(noop));
});`);
  });

  it('fires on .finally with no .catch', () => {
    // finally runs on rejection, it does not handle it.
    fires(`
btn.addEventListener('click', async () => {
  await sync().finally(() => spinner.stop());
});`);
  });

  it('stays quiet when every await carries its own .catch', () => {
    quiet(`
btn.addEventListener('click', async () => {
  const a = await load().catch(() => null);
  const b = await save(a).catch(() => null);
  render(a, b);
});`);
  });
});

describe('a try block guards only what it encloses', () => {
  it('fires when the try covers the first await and not the second', () => {
    fires(`
btn.addEventListener('click', async () => {
  try { await validateForm(); } catch (err) { showErrors(err); return; }
  await submitForm();
});`);
  });

  it('stays quiet when the whole body is wrapped', () => {
    quiet(`
btn.addEventListener('click', async () => {
  try {
    const r = await fetch('/x');
    render(await r.json());
  } catch (e) { show(e); }
});`);
  });

  it('fires when the catch clause itself awaits', () => {
    // A catch handles the try block's failure, not its own. If report() rejects,
    // the listener rejects with nothing to catch it. The first implementation
    // credited the whole try statement, including its clauses, and an
    // adversarial round rejected that: it is the same category error as the
    // wrong-promise .catch above, just written with different syntax.
    fires(`
btn.addEventListener('click', async () => {
  try { await save(); } catch (e) { await report(e); }
});`);
  });

  it('fires on try/finally with no catch clause', () => {
    // finally runs on the way past. It does not consume the rejection.
    fires(`
btn.addEventListener('click', async () => {
  try { await save(); } finally { spinner.stop(); }
});`);
  });

  it('stays quiet on nested try/catch', () => {
    quiet(`
btn.addEventListener('click', async () => {
  try {
    try { await inner(); } catch (e) { await fallback(); }
  } catch (e) { log(e); }
});`);
  });
});

describe('an await belongs to the function that contains it', () => {
  it('fires on the outer await even when a nested callback is guarded', () => {
    fires(`
btn.addEventListener('click', async () => {
  items.forEach(async (x) => { try { await save(x); } catch (e) { log(e); } });
  await publish();
});`);
  });

  it('stays quiet when the only await lives in a nested function', () => {
    quiet(`
btn.addEventListener('click', async () => {
  const go = async () => { await save(); };
  register(go);
});`);
  });
});

describe('fire-and-forget sinks, and what is not one', () => {
  it('fires on an unguarded await in a setTimeout callback', () => {
    fires(`
setTimeout(async () => {
  await refresh();
}, 1000);`);
  });

  it('fires on an unguarded await inside a loop', () => {
    fires(`
btn.addEventListener('click', async () => {
  for (const x of items) { await save(x); }
});`);
  });

  it('fires on an unguarded await Promise.all', () => {
    fires(`
btn.addEventListener('click', async () => {
  await Promise.all(items.map(save));
});`);
  });

  it('stays quiet on a plain async function declaration', () => {
    // Its caller may correctly handle the rejection.
    quiet(`
async function loadThings() {
  const r = await fetch('/x');
  return r.json();
}`);
  });

  it('stays quiet on an async callback with no await at all', () => {
    quiet(`
btn.addEventListener('click', async () => {
  render(cached);
});`);
  });
});

describe('trigger shapes that are not code', () => {
  it('stays quiet on an await written inside a string', () => {
    quiet(`
btn.addEventListener('click', async () => {
  const doc = "await fetch(url) with no try";
  render(doc);
});`);
  });

  it('stays quiet on an await written inside a comment', () => {
    quiet(`
btn.addEventListener('click', async () => {
  // await fetch(url) would be unguarded here
  render(1);
});`);
  });

  it('does not read await as part of a longer identifier', () => {
    quiet(`
btn.addEventListener('click', async () => {
  const awaitable = makeAwaitable();
  render(awaitable);
});`);
  });
});

describe('the finding points at the exposed await', () => {
  it('names the line and the expression that has no handler', () => {
    const found = run(`
$('pwSave').addEventListener('click', async () => {
  const r = await fetch('/api/auth/password', { method: 'POST' });
  const j = await r.json().catch(() => ({}));
});`);
    expect(found).toHaveLength(1);
    // The reader should not have to re-derive which await is the problem.
    expect(found[0].evidence).toMatch(/unguarded at line 3/);
    expect(found[0].evidence).toContain('fetch');
    expect(found[0].evidence).not.toContain('r.json()');
  });
});
