// Vitest setup — runs once before each test file.
// jsdom already provides localStorage, but ensure a clean state per test if needed via the helpers below.

if (typeof globalThis.performance === 'undefined' || !globalThis.performance.now) {
  globalThis.performance = { now: () => Date.now() };
}
