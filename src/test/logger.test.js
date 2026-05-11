import { describe, it, expect, beforeEach } from 'vitest';
import {
  createLogger,
  log,
  getLogs,
  clearLogs,
  subscribe,
  setMinLevel,
  setBufferLimit,
  exportLogs,
} from '../lib/logger.js';

describe('logger', () => {
  beforeEach(() => {
    clearLogs();
    setMinLevel('debug');
    setBufferLimit(500);
  });

  it('records all four levels', () => {
    log.debug('d');
    log.info('i');
    log.warn('w');
    log.error('e');
    const all = getLogs();
    expect(all.map((x) => x.level)).toEqual(['debug', 'info', 'warn', 'error']);
  });

  it('respects minLevel filter', () => {
    setMinLevel('warn');
    log.debug('d');
    log.info('i');
    log.warn('w');
    log.error('e');
    expect(getLogs().map((x) => x.level)).toEqual(['warn', 'error']);
  });

  it('attaches scope from createLogger', () => {
    const sub = createLogger('billing');
    sub.info('charged');
    expect(getLogs()[0].scope).toBe('billing');
  });

  it('chained scopes use colon separator', () => {
    const sub = createLogger('billing').child('refund');
    sub.warn('partial');
    expect(getLogs()[0].scope).toBe('billing:refund');
  });

  it('rings the buffer at the configured limit', () => {
    setBufferLimit(3);
    for (let i = 0; i < 10; i++) log.info(`m${i}`);
    const all = getLogs();
    expect(all).toHaveLength(3);
    // Ring keeps the most recent.
    expect(all.map((x) => x.message)).toEqual(['m7', 'm8', 'm9']);
  });

  it('notifies subscribers on emit', () => {
    let calls = 0;
    const unsub = subscribe(() => {
      calls++;
    });
    log.info('a');
    log.info('b');
    expect(calls).toBe(2);
    unsub();
    log.info('c');
    expect(calls).toBe(2); // no longer subscribed
  });

  it('exportLogs is parseable JSON', () => {
    log.info('x');
    const parsed = JSON.parse(exportLogs());
    expect(parsed[0].message).toBe('x');
  });

  it('serializes Error objects in context safely', () => {
    log.error('boom', new Error('crash'));
    const e = getLogs()[0];
    expect(e.context).toBeInstanceOf(Error);
    expect(JSON.parse(exportLogs())[0]).toBeDefined(); // does not throw
  });

  // REGRESSION: circular context used to permanently break Diagnostics Copy / Save / persist.
  it('REGRESSION: circular context object does not break exportLogs', () => {
    const obj = { name: 'cyclic' };
    obj.self = obj;
    log.error('cycle', obj);
    expect(() => exportLogs()).not.toThrow();
    const parsed = JSON.parse(exportLogs());
    expect(parsed[0].context).toBeDefined();
    // The cycle should have been replaced with a sentinel.
    expect(JSON.stringify(parsed)).toMatch(/\[Circular\]/);
  });

  it('exportLogs handles BigInt and functions in context', () => {
    log.info('weird', { big: 10n, fn: () => 'noop' });
    expect(() => exportLogs()).not.toThrow();
  });
});
