// The axes have to reach a surface, not just exist in the library.
//
// computeScores shipped correct and unit-tested but nothing outside the tests
// called it, so users still saw a single number. These assert the seams that
// carry it: the cockpit scan result, and the ScoreAxes element tree the
// results view renders.
//
// ScoreAxes is exercised by calling it and walking the returned elements.
// @testing-library/react is not a dependency on main (component tests live on
// the breakers branch), and a pure function returning JSX does not need a DOM
// to be checked.
import { describe, it, expect } from 'vitest';
import { scan } from '../lib/cockpit-scan.js';
import { ScoreAxes } from '../components/ScoreDisplay.jsx';
import { SCORE_AXES } from '../lib/scoring.js';

// Flatten a React element tree to its rendered text content.
function textOf(node) {
  if (node === null || node === undefined || node === false) return '';
  if (typeof node === 'string' || typeof node === 'number') return String(node);
  if (Array.isArray(node)) return node.map(textOf).join(' ');
  if (typeof node === 'object' && node.props) return textOf(node.props.children);
  return '';
}

describe('cockpit scan returns the per-area breakdown', () => {
  // A security finding without a credential-shaped literal. An earlier version
  // of this fixture used a Stripe-live-key shape to force a Secret Scanner
  // hit, and GitHub push protection rejected the commit — correctly. A test
  // fixture that trips real secret scanners is a liability in every clone.
  const files = [
    {
      path: 'src/app.js',
      content: ['export function run(input) {', '  return eval(input);', '}'].join('\n'),
    },
  ];

  it('includes scores alongside the headline number', () => {
    const r = scan(files);
    expect(typeof r.score).toBe('number');
    expect(r.scores).toBeTruthy();
    for (const axis of SCORE_AXES) {
      expect(typeof r.scores[axis].score).toBe('number');
      expect(typeof r.scores[axis].findings).toBe('number');
    }
  });

  it('keeps the headline number equal to the security axis', () => {
    const r = scan(files);
    expect(r.score).toBe(r.scores.security.score);
  });

  it('does not break on an empty scan', () => {
    const r = scan([]);
    expect(r.scores.security.score).toBe(100);
    expect(r.scores.health.findings).toBe(0);
  });
});

describe('ScoreAxes renders what the scan produced', () => {
  const scores = {
    security: { score: 90, findings: 2 },
    health: { score: 60, findings: 12 },
    accessibility: { score: 100, findings: 0 },
    discoverability: { score: 98, findings: 1 },
  };
  const text = () => textOf(ScoreAxes({ scores }));

  it('labels every area', () => {
    const t = text();
    for (const label of ['Security', 'Code health', 'Accessibility', 'Discoverability']) {
      expect(t).toContain(label);
    }
  });

  it('shows a score where findings exist', () => {
    const t = text();
    expect(t).toContain('90 / 100');
    expect(t).toContain('60 / 100');
  });

  it('says "clear" rather than a confident 100 where nothing was found', () => {
    expect(text()).toContain('clear');
    expect(text()).not.toContain('100 / 100');
  });

  it('states that non-security areas do not affect the risk score', () => {
    const matches = text().match(/does not affect the risk score/g) || [];
    // health and discoverability have findings; accessibility is clear.
    expect(matches.length).toBe(2);
  });

  it('does not claim the security axis is advisory', () => {
    const t = textOf(ScoreAxes({ scores: { security: { score: 80, findings: 3 } } }));
    expect(t).not.toContain('does not affect the risk score');
  });

  it('renders nothing without data rather than throwing', () => {
    expect(ScoreAxes({ scores: null })).toBeNull();
    expect(ScoreAxes({ scores: {} })).toBeNull();
  });
});
