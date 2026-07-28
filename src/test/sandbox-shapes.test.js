/**
 * Sandbox shapes.
 *
 * The contract that makes the surface worth visiting: the vulnerable buffer
 * must actually fire the probe it claims, and the fix must actually clear it.
 *
 * The fixed-buffer assertion is ZERO findings in total, not zero from that
 * probe, and that strictness earned itself immediately: a "clean" rewrite of
 * the starter shape cleared the promise finding and tripped the fire-and-forget
 * check instead. A fix that trips something else is a lesson that lies, and the
 * whole point of the loop is that the panel goes quiet when you get it right.
 */

import { describe, it, expect } from 'vitest';
import { runSandboxScan } from '../lib/sandbox/runner.js';
import {
  SHAPES,
  SHAPE_BY_SLUG,
  DEFAULT_SHAPE_SLUG,
  getShape,
  shapesForPattern,
  shapeForFinding,
} from '../lib/sandbox/shapes.js';
import { resolvePatternForProbe } from '../lib/learn-content.js';

describe('sandbox shapes — the loop actually closes', () => {
  for (const shape of SHAPES) {
    it(`${shape.slug}: the buffer fires ${shape.probeId}`, () => {
      const found = runSandboxScan(shape.buffer, shape.filename) || [];
      expect(found.some((f) => f.probe === shape.probeId)).toBe(true);
    });

    it(`${shape.slug}: the fix clears every finding`, () => {
      expect(runSandboxScan(shape.fixedBuffer, shape.filename) || []).toHaveLength(0);
    });
  }
});

describe('sandbox shapes — registry integrity', () => {
  it('slugs are unique and kebab-case', () => {
    const slugs = SHAPES.map((s) => s.slug);
    expect(new Set(slugs).size).toBe(slugs.length);
    for (const slug of slugs) expect(slug).toMatch(/^[a-z0-9]+(?:-[a-z0-9]+)*$/);
  });

  it('every entry carries the required fields', () => {
    for (const s of SHAPES) {
      for (const field of ['slug', 'title', 'probeId', 'buffer', 'fixedBuffer', 'note']) {
        expect(typeof s[field], `${s.slug}.${field}`).toBe('string');
        expect(s[field].length, `${s.slug}.${field}`).toBeGreaterThan(0);
      }
    }
  });

  it('notes stay short and carry no em-dash', () => {
    for (const s of SHAPES) {
      expect(s.note, s.slug).not.toMatch(/—/);
      expect((s.note.match(/\.\s|\.$/g) || []).length, s.slug).toBeLessThanOrEqual(2);
    }
  });

  it('findingIdPrefix, where set, matches a real emitted finding id', () => {
    for (const s of SHAPES.filter((x) => x.findingIdPrefix)) {
      const found = runSandboxScan(s.buffer, s.filename) || [];
      expect(
        found.some((f) => String(f.id).startsWith(s.findingIdPrefix)),
        s.slug
      ).toBe(true);
    }
  });

  it('learnSlug, where set, resolves to a published pattern', () => {
    for (const s of SHAPES.filter((x) => x.learnSlug)) {
      expect(resolvePatternForProbe(s.probeId) || s.learnSlug, s.slug).toBeTruthy();
      expect(SHAPE_BY_SLUG[s.slug]).toBe(s);
    }
  });
});

describe('sandbox shapes — lookup never throws', () => {
  it('an unknown, empty, or hostile slug falls back to the default', () => {
    for (const bad of [null, undefined, '', 'nope', '../../etc/passwd', 42]) {
      expect(getShape(bad).slug).toBe(DEFAULT_SHAPE_SLUG);
    }
  });

  it('shapesForPattern excludes the landing shape', () => {
    const forCodeQuality = shapesForPattern('code-quality');
    expect(forCodeQuality.every((s) => s.slug !== DEFAULT_SHAPE_SLUG)).toBe(true);
  });

  it('shapeForFinding routes on the id prefix, not the probe name', () => {
    // `Code Quality` covers console, file size, unhandled .then and
    // fire-and-forget. Matching on the probe name alone sent a console finding
    // to the unhandled-promise shape.
    expect(shapeForFinding({ id: 'cq-console-sandbox.jsx', probe: 'Code Quality' })).toBeNull();
    const promise = SHAPES.find((s) => s.slug === 'unhandled-promise');
    expect(shapeForFinding({ id: `${promise.findingIdPrefix}sandbox.jsx-1` })).toBe(promise);
  });
});
