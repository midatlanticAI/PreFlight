// Adversarial PRECISION suite, round 1: unhandled-async-rejection over-fire hunting.
// Every fixture here is benign JavaScript/JSX where a naive "unhandled async
// rejection" scanner would over-fire. Each test asserts ZERO findings whose
// title matches /fire-and-forget|try\/catch/i.
//
// Fixtures use production-looking paths, stay under 100 lines, and contain no
// console.* calls so unrelated code-quality findings stay out of the way.

import { describe, it, expect } from 'vitest';
import { probeCodeQuality } from '../lib/probes.js';

function asyncFindings(path, content) {
  const findings = probeCodeQuality([{ path, content }]);
  return findings.filter((f) => /fire-and-forget|try\/catch/i.test(f.title));
}

function expectClean(path, content) {
  expect(asyncFindings(path, content)).toEqual([]);
}

// For fixtures in the ambiguous set that adjudication resolved as real findings.
function expectFires(path, content) {
  expect(asyncFindings(path, content).length).toBeGreaterThan(0);
}

describe('category 1: async sink callbacks WITH try/catch around their awaits', () => {
  it('async addEventListener callback with try/catch wrapping the await', () => {
    expectClean(
      'src/app.js',
      `
const button = document.querySelector('#save');
button.addEventListener('click', async () => {
  try {
    await saveDocument();
  } catch (err) {
    showToast(err.message);
  }
});
`
    );
  });

  it('async setTimeout callback with try/catch wrapping the await', () => {
    expectClean(
      'src/scheduler.js',
      `
export function schedulePoll() {
  setTimeout(async () => {
    try {
      const status = await pollServer();
      updateBadge(status);
    } catch (err) {
      markOffline(err);
    }
  }, 5000);
}
`
    );
  });

  it('async setInterval callback with try/catch wrapping the await', () => {
    expectClean(
      'src/heartbeat.js',
      `
export function startHeartbeat(client) {
  return setInterval(async () => {
    try {
      await client.ping();
    } catch (err) {
      client.reconnect(err);
    }
  }, 30000);
}
`
    );
  });

  it('async inline JSX onClick handler with try/catch wrapping the await', () => {
    expectClean(
      'src/components/SaveBar.jsx',
      `
export function SaveBar({ onSaved, notify }) {
  return (
    <button
      onClick={async () => {
        try {
          await persistDraft();
          onSaved();
        } catch (err) {
          notify(err);
        }
      }}
    >
      Save
    </button>
  );
}
`
    );
  });
});

describe('category 2: async callbacks whose body has no await at all', () => {
  it('async addEventListener callback with no await in the body', () => {
    expectClean(
      'src/counter.js',
      `
let count = 0;
document.addEventListener('click', async () => {
  count += 1;
  updateCounterLabel(count);
});
`
    );
  });

  it('async setTimeout callback with an expression body and no await', () => {
    expectClean(
      'src/queue.js',
      `
export function enqueueLater(queue, job) {
  setTimeout(async () => queue.push(job), 0);
}
`
    );
  });

  it('async JSX onClick handler with no await in the body', () => {
    expectClean(
      'src/components/Toggle.jsx',
      `
export function Toggle({ setOpen }) {
  return <button onClick={async () => setOpen(true)}>Open</button>;
}
`
    );
  });
});

describe('category 3: sync callbacks passed to the same sinks', () => {
  it('sync arrow passed to addEventListener', () => {
    expectClean(
      'src/scroll.js',
      `
window.addEventListener('scroll', () => {
  updateScrollPosition(window.scrollY);
});
`
    );
  });

  it('sync arrow passed to setTimeout', () => {
    expectClean(
      'src/ticker.js',
      `
export function delayTick() {
  setTimeout(() => tick(), 500);
}
`
    );
  });

  it('sync function expression to setInterval and sync JSX onChange', () => {
    expectClean(
      'src/components/Carousel.jsx',
      `
export function Carousel({ setValue }) {
  setInterval(function rotateSlides() {
    rotate();
  }, 4000);
  return <input onChange={(e) => setValue(e.target.value)} />;
}
`
    );
  });
});

describe('category 4: async functions never called bare (await/void/.catch/.then/return/assigned)', () => {
  it('async function declared and exported but never called', () => {
    expectClean(
      'src/migrate.js',
      `
async function main() {
  const cfg = await loadConfig();
  await applyMigrations(cfg);
  return cfg;
}

export { main };
`
    );
  });

  it('async arrow assignment called with await', () => {
    expectClean(
      'src/cli.js',
      `
const main = async () => {
  await migrate();
  await seed();
};

export async function cli() {
  await main();
}
`
    );
  });

  it('async function called with the void operator', () => {
    expectClean(
      'src/idle.js',
      `
async function main() {
  await warmCache();
}

export function onIdle() {
  void main();
}
`
    );
  });

  it('async function called with .catch attached', () => {
    expectClean(
      'src/boot.js',
      `
async function main() {
  await connectDatabase();
}

export function boot(handleErr) {
  main().catch(handleErr);
}
`
    );
  });

  it('async function called with two-argument .then (rejection handler present)', () => {
    expectClean(
      'src/sync.js',
      `
async function main() {
  await pushChanges();
}

export function runSync(onDone, onFail) {
  main().then(onDone, onFail);
}
`
    );
  });

  it('async function call returned from the caller', () => {
    expectClean(
      'src/runner.js',
      `
async function main() {
  await buildIndex();
}

export function start() {
  return main();
}
`
    );
  });

  it('promise assigned to a local and awaited later in the same function', () => {
    expectClean(
      'src/warmup.js',
      `
async function main() {
  await prefetchAssets();
}

export async function warmup() {
  const pending = main();
  prepareUi();
  await pending;
}
`
    );
  });
});

describe('category 5: async calls as arguments, in array literals, in return statements', () => {
  it('async calls inside Promise.all argument array', () => {
    expectClean(
      'src/startup.js',
      `
async function main() {
  await loadPrimary();
}

async function backup() {
  await loadSecondary();
}

export async function startAll() {
  await Promise.all([main(), backup()]);
}
`
    );
  });

  it('async call in an array literal that is awaited via allSettled', () => {
    expectClean(
      'src/batch.js',
      `
async function main() {
  await flushBatch();
}

export async function drainAll() {
  const tasks = [main(), rotateLogs()];
  const results = await Promise.allSettled(tasks);
  return results;
}
`
    );
  });

  it('async call in a return statement of a sync wrapper', () => {
    expectClean(
      'src/wrapper.js',
      `
async function main() {
  await compileTemplates();
}

export function precompile() {
  return main();
}
`
    );
  });

  it('async call passed as an argument to a runner that owns the promise', () => {
    expectClean(
      'src/pool.js',
      `
async function main() {
  await processQueue();
}

export async function withRetry(runner) {
  await runner(main());
}
`
    );
  });
});

describe('category 6: same NAME as a local async function, but a different callee', () => {
  it('member call api.main() does not resolve to the local async main', () => {
    expectClean(
      'src/deploy.js',
      `
async function main() {
  await deployRelease();
}

export async function trigger(api) {
  api.main();
  await main();
}
`
    );
  });

  it('bare call resolves to a sync local shadow, not the outer async function', () => {
    expectClean(
      'src/data.js',
      `
async function fetchData() {
  const res = await http.get('/data');
  return res.body;
}

export function refreshLocal(cache) {
  const fetchData = () => cache.read('data');
  fetchData();
}

export { fetchData };
`
    );
  });

  it('object method sharing the async function name, called on the object', () => {
    expectClean(
      'src/jobs.js',
      `
async function main() {
  await syncAll();
}

const jobs = {
  main() {
    return scheduler.flush();
  },
};

export function runJobs() {
  jobs.main();
}

export { main };
`
    );
  });
});

describe('category 7: strings and comments containing the trigger shapes', () => {
  it('single-line comment containing main(); and setTimeout(async', () => {
    expectClean(
      'src/tool.js',
      `
async function main() {
  await runAudit();
}

// Manual usage: main();
// Do NOT write setTimeout(async () => { await main(); }, 0); here.
export { main };
`
    );
  });

  it('block comment containing the bare call and async timer shapes', () => {
    expectClean(
      'src/migrate-cli.js',
      `
async function main() {
  await db.migrate();
}

/*
  To run manually from a REPL:
    main();
    setTimeout(async () => { await main(); }, 0);
  Both are documented, not executed.
*/
export default main;
`
    );
  });

  it('template literal containing the trigger shapes as documentation text', () => {
    expectClean(
      'src/docs.js',
      `
async function main() {
  await runAll();
}

const usage = \`
Call it yourself:
  main();
  setTimeout(async () => { await main(); }, 1000);
\`;

export { main, usage };
`
    );
  });

  it('regular string containing the trigger shapes', () => {
    expectClean(
      'src/snippets.js',
      `
async function main() {
  await start();
}

const example = 'main(); setTimeout(async () => { await main(); }, 50);';
const doubled = "if (ready) main();";

export { main, example, doubled };
`
    );
  });
});

describe('category 8: async IIFEs with a rejection handler attached', () => {
  it('async arrow IIFE with .catch attached', () => {
    expectClean(
      'src/bootstrap.js',
      `
(async () => {
  await bootApplication();
})().catch(reportFatal);
`
    );
  });

  it('named async function expression IIFE with inline .catch handler', () => {
    expectClean(
      'src/init.js',
      `
(async function init() {
  await loadSettings();
  await mountRoot();
})().catch((err) => notifyOps(err));
`
    );
  });

  it('void async IIFE whose body is fully wrapped in try/catch', () => {
    expectClean(
      'src/prewarm.js',
      `
void (async () => {
  try {
    await warmEdgeCache();
  } catch (err) {
    metrics.record('prewarm_failed', err);
  }
})();
`
    );
  });
});

describe('category 9: statement-position calls to functions that are NOT async in this file', () => {
  it('bare call to a sync function declaration', () => {
    expectClean(
      'src/refresh.js',
      `
function refresh() {
  rebuildMenu();
  repaintHeader();
}

refresh();
`
    );
  });

  it('bare call to a sync arrow assignment', () => {
    expectClean(
      'src/metronome.js',
      `
const tick = () => {
  advanceClock();
};

export function step() {
  tick();
}
`
    );
  });

  it('hoisted sync function called before its declaration', () => {
    expectClean(
      'src/wire.js',
      `
setup();

function setup() {
  wireHandlers();
  registerShortcuts();
}
`
    );
  });
});

describe('category 10: React useEffect calling an inner async function it defines and catches', () => {
  it('inner async arrow in useEffect, invoked with .catch(setError)', () => {
    expectClean(
      'src/components/Profile.jsx',
      `
import { useEffect, useState } from 'react';

export function Profile({ id }) {
  const [user, setUser] = useState(null);
  const [error, setError] = useState(null);
  useEffect(() => {
    const load = async () => {
      const res = await fetch('/api/users/' + id);
      setUser(await res.json());
    };
    load().catch(setError);
  }, [id]);
  return <div>{error ? 'failed' : user ? user.name : 'loading'}</div>;
}
`
    );
  });

  it('inner async function declaration in useEffect, invoked with .catch', () => {
    expectClean(
      'src/components/Feed.jsx',
      `
import { useEffect, useState } from 'react';

export function Feed({ topic, onError }) {
  const [items, setItems] = useState([]);
  useEffect(() => {
    async function loadFeed() {
      const res = await fetch('/api/feed?topic=' + topic);
      setItems(await res.json());
    }
    loadFeed().catch(onError);
  }, [topic, onError]);
  return <ul>{items.map((i) => <li key={i.id}>{i.title}</li>)}</ul>;
}
`
    );
  });

  it('async IIFE inside useEffect with .catch and a cleanup return', () => {
    expectClean(
      'src/components/Detail.jsx',
      `
import { useEffect, useState } from 'react';

export function Detail({ id, reportError }) {
  const [doc, setDoc] = useState(null);
  useEffect(() => {
    let alive = true;
    (async () => {
      const res = await fetch('/api/docs/' + id);
      const body = await res.json();
      if (alive) setDoc(body);
    })().catch(reportError);
    return () => {
      alive = false;
    };
  }, [id, reportError]);
  return <article>{doc ? doc.title : 'loading'}</article>;
}
`
    );
  });
});

describe('category 11: JSX handler props referencing a named async handler with try/catch', () => {
  it('onClick={handleSave} where handleSave is async with try/catch', () => {
    expectClean(
      'src/components/Editor.jsx',
      `
export function Editor({ notify }) {
  const handleSave = async () => {
    try {
      await persistDocument();
      notify('saved');
    } catch (err) {
      notify(err.message);
    }
  };
  return <button onClick={handleSave}>Save</button>;
}
`
    );
  });

  it('onSubmit={handleSubmit} where handleSubmit is async with try/catch', () => {
    expectClean(
      'src/components/SignupForm.jsx',
      `
export function SignupForm({ setStatus }) {
  async function handleSubmit(event) {
    event.preventDefault();
    try {
      await submitSignup(new FormData(event.target));
      setStatus('ok');
    } catch (err) {
      setStatus('error');
    }
  }
  return <form onSubmit={handleSubmit}><button type="submit">Join</button></form>;
}
`
    );
  });

  it('onChange={handleChange} where handleChange is async with try/catch', () => {
    expectClean(
      'src/components/AvatarPicker.jsx',
      `
export function AvatarPicker({ setPreview, setFault }) {
  const handleChange = async (event) => {
    try {
      const url = await uploadAvatar(event.target.files[0]);
      setPreview(url);
    } catch (err) {
      setFault(err);
    }
  };
  return <input type="file" onChange={handleChange} />;
}
`
    );
  });
});

describe('category 12: async generators and for-await-of in properly awaited contexts', () => {
  it('async generator consumed with for-await inside an exported async function', () => {
    expectClean(
      'src/paginate.js',
      `
async function* pages(url) {
  let next = url;
  while (next) {
    const res = await fetch(next);
    const body = await res.json();
    next = body.next;
    yield body.items;
  }
}

export async function collectAll(url) {
  const out = [];
  for await (const batch of pages(url)) {
    out.push(...batch);
  }
  return out;
}
`
    );
  });

  it('for-await-of wrapped in try/catch inside an exported async function', () => {
    expectClean(
      'src/stream.js',
      `
export async function readStream(stream, onChunk, onFault) {
  try {
    for await (const chunk of stream) {
      onChunk(chunk);
    }
  } catch (err) {
    onFault(err);
  }
}
`
    );
  });

  it('async generator passed as an argument to an awaited drain call', () => {
    expectClean(
      'src/rows.js',
      `
async function* readRows(db) {
  for (const table of await db.tables()) {
    yield await db.dump(table);
  }
}

export async function exportAll(db, drain) {
  const rows = await drain(readRows(db));
  return rows;
}
`
    );
  });
});

describe('category 13: class methods where the call line contains await or return', () => {
  it('async class method awaited via this.method() in another method', () => {
    expectClean(
      'src/service.js',
      `
export class Service {
  async main() {
    await this.client.connect();
  }

  async run() {
    await this.main();
    return this.client.status();
  }
}
`
    );
  });

  it('sync class method returning this.asyncMethod()', () => {
    expectClean(
      'src/loader.js',
      `
export class Loader {
  async load() {
    this.data = await fetchManifest();
  }

  refresh() {
    return this.load();
  }
}
`
    );
  });

  it('instance method named main awaited by an exported async bootstrap', () => {
    expectClean(
      'src/bootstrap-service.js',
      `
class Worker {
  async main() {
    await this.channel.open();
  }
}

export async function bootstrap() {
  const worker = new Worker();
  await worker.main();
  return worker;
}
`
    );
  });
});

describe('category 14: chained calls on the async invocation', () => {
  it('statement-position main().finally(cleanup) chain', () => {
    expectClean(
      'src/shutdown.js',
      `
async function main() {
  await job.run();
}

export function shutdownHook(releaseLock) {
  main().finally(releaseLock);
}
`
    );
  });

  it('statement-position main().catch(report).finally(cleanup) chain', () => {
    expectClean(
      'src/task.js',
      `
async function main() {
  await runTask();
}

export function launch(report, cleanup) {
  main().catch(report).finally(cleanup);
}
`
    );
  });

  it('finally-chained promise assigned and awaited', () => {
    expectClean(
      'src/spinner.js',
      `
async function main() {
  await hydrateStore();
}

export async function hydrate(stopSpinner) {
  const pending = main().finally(stopSpinner);
  await pending;
}
`
    );
  });
});

describe('category 15: conditional and short-circuit calls', () => {
  it('if (ready) await main(); inside an async function', () => {
    expectClean(
      'src/gate.js',
      `
async function main() {
  await openGate();
}

export async function maybeOpen(ready) {
  if (ready) await main();
}
`
    );
  });

  it('short-circuit ready && main().catch(log);', () => {
    expectClean(
      'src/lazy.js',
      `
async function main() {
  await loadPlugins();
}

export function kick(ready, log) {
  ready && main().catch(log);
}
`
    );
  });

  it('ternary picking between two async calls, each with .catch', () => {
    expectClean(
      'src/route.js',
      `
async function fastPath() {
  await servefromCache();
}

async function slowPath() {
  await rebuildAndServe();
}

export function route(useFast, report) {
  useFast ? fastPath().catch(report) : slowPath().catch(report);
}
`
    );
  });
});

// These fixtures sit on the real boundary between benign and unhandled. A
// maximally precise probe would stay quiet on all of them, but firing on some
// is defensible. Failures here are signal for calibration, not regressions.
describe('edge cases where benign-vs-unhandled is genuinely ambiguous', () => {
  // ADJUDICATED round 2 (2026-07): the probe became await-level, so this now
  // fires, and firing is the correct answer. `await submitForm()` sits outside
  // the try and can genuinely reject with nothing to handle it. This author
  // predicted the outcome in the original comment below; the expectation is
  // flipped rather than the finding suppressed.
  it('RESOLVED: try/catch covers only the first await, so the second still fires', () => {
    // The second await CAN produce an unhandled rejection. A probe that
    // requires "no try/catch at all" stays quiet; an await-level probe fires.
    expectFires(
      'src/partial.js',
      `
document.addEventListener('submit', async () => {
  try {
    await validateForm();
  } catch (err) {
    showErrors(err);
    return;
  }
  await submitForm();
});
`
    );
  });

  // ADJUDICATED round 1: kept firing. Proving the body cannot reject needs
  // inter-procedural analysis; the low-severity advisory to add .catch/void
  // is still correct discipline at the call site.
  it.skip('AMBIGUOUS: bare main() whose entire body is wrapped in try/catch', () => {
    // main() can never reject (its body swallows everything), so the bare
    // call is harmless. A call-site-only scanner fires; a body-aware one
    // does not.
    expectClean(
      'src/selfcontained.js',
      `
async function main() {
  try {
    await pruneCache();
  } catch (err) {
    recordFailure(err);
  }
}

export function onVisible() {
  main();
}
`
    );
  });

  it('AMBIGUOUS: async timer body handles rejection per-await via .catch, no try/catch', () => {
    // Every await operand carries its own .catch, so nothing escapes, but the
    // body "contains await with no try/catch" and matches the naive shape.
    expectClean(
      'src/perawait.js',
      `
export function pollLoop(swallow) {
  setInterval(async () => {
    const status = await checkHealth().catch(swallow);
    if (status) renderStatus(status);
  }, 10000);
}
`
    );
  });

  // ADJUDICATED round 1: kept firing. A global unhandledrejection handler is
  // a last-resort net, not a handler for this call; the advisory stands.
  it.skip('AMBIGUOUS: bare main() under a registered global unhandledrejection handler', () => {
    // The rejection IS observed, just at the global level. Whether that
    // counts as "handled" is a policy call.
    expectClean(
      'src/global-handler.js',
      `
window.addEventListener('unhandledrejection', (event) => {
  reportToDiagnostics(event.reason);
  event.preventDefault();
});

async function main() {
  await refreshSession();
}

export function onFocus() {
  main();
}
`
    );
  });
});
