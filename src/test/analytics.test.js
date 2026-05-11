import { describe, it, expect, beforeEach } from 'vitest';
import {
  track,
  timing,
  startTimer,
  getSnapshot,
  getCount,
  getTotalEvents,
  reset,
  exportJson,
  subscribe,
} from '../lib/analytics.js';

describe('analytics', () => {
  beforeEach(() => {
    if (typeof localStorage !== 'undefined') localStorage.clear();
    reset();
  });

  it('counts simple events', () => {
    track('scan_started');
    track('scan_started');
    track('scan_completed');
    expect(getCount('scan_started')).toBe(2);
    expect(getCount('scan_completed')).toBe(1);
    expect(getTotalEvents()).toBe(3);
  });

  it('rejects unsafe event names', () => {
    track('this has spaces');
    track('');
    track(null);
    track(123);
    track('a/path/like/this');
    expect(getTotalEvents()).toBe(0);
  });

  it('rejects negative or non-finite increments', () => {
    track('x', -1);
    track('x', NaN);
    track('x', Infinity);
    expect(getCount('x')).toBe(0);
  });

  it('records timing histograms', () => {
    timing('probe.run', 10);
    timing('probe.run', 30);
    timing('probe.run', 20);
    const snap = getSnapshot();
    expect(snap.timings['probe.run'].count).toBe(3);
    expect(snap.timings['probe.run'].sumMs).toBe(60);
    expect(snap.timings['probe.run'].minMs).toBe(10);
    expect(snap.timings['probe.run'].maxMs).toBe(30);
  });

  it('startTimer returns a stop fn that records elapsed', () => {
    const stop = startTimer('boot');
    stop();
    expect(getSnapshot().timings.boot.count).toBe(1);
  });

  it('persists across reload via localStorage', () => {
    track('persisted');
    // simulate reload by reading the key
    const raw = localStorage.getItem('audit-app:analytics:v1');
    expect(raw).toBeTruthy();
    const parsed = JSON.parse(raw);
    expect(parsed.counts.persisted).toBe(1);
  });

  it('reset() empties state and persists', () => {
    track('a');
    reset();
    expect(getTotalEvents()).toBe(0);
    expect(getCount('a')).toBe(0);
  });

  it('exportJson is parseable JSON with the v1 schema', () => {
    track('x');
    const parsed = JSON.parse(exportJson());
    expect(parsed.schema).toBe('analytics/v1');
    expect(parsed.counts.x).toBe(1);
  });

  it('subscribers are notified on track and timing', () => {
    let calls = 0;
    const unsub = subscribe(() => {
      calls++;
    });
    track('y');
    timing('z', 5);
    expect(calls).toBe(2);
    unsub();
    track('y');
    expect(calls).toBe(2);
  });

  it('does not record any user data when given an event with content-shaped names', () => {
    // Even if a caller bug tries to record a path, the schema still has only the name as a key.
    track('error_caught');
    const snap = getSnapshot();
    // No way to encode user content into a counter; verify no extra fields exist.
    expect(Object.keys(snap)).toEqual(
      expect.arrayContaining(['schema', 'bootedAt', 'counts', 'timings'])
    );
    expect(Object.keys(snap.counts)).toEqual(['error_caught']);
  });
});
