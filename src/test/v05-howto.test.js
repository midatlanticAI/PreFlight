// The "How it works" reference page must cover the whole feature surface
// and obey the manifesto voice (no slop, no em-dash, no live script).

import { describe, it, expect } from 'vitest';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { HowToView } from '../components/learn/HowToView.jsx';

const html = renderToStaticMarkup(React.createElement(HowToView));
const text = html.replace(/<[^>]+>/g, ' ');

describe('HowToView: coverage', () => {
  it('documents every major feature surface', () => {
    for (const topic of [
      'How it works',
      'GitHub URL',
      'Local folder',
      'OWASP',
      'MAPS TO',
      'Breakers',
      'Explain',
      'Suppress',
      'compliance lens',
      'not everything fires',
      'What it is not',
    ]) {
      expect(text, `missing: ${topic}`).toContain(topic);
    }
  });

  it('explains scoped coverage (the user-raised "not everything fires")', () => {
    expect(text).toMatch(/scoped to the files/i);
    expect(text).toMatch(/stay silent by design/i);
  });
});

describe('HowToView: voice + safety', () => {
  it('no live script tag in the rendered markup', () => {
    expect(html).not.toMatch(/<script\b/i);
  });

  it('no em-dash and no AI-slop words in the copy', () => {
    expect(text.includes('—'), 'em-dash in How-it-works copy').toBe(false);
    expect(
      /\b(comprehensive|seamless|robust|powerful|leverage|utilize|delve|harness|unlock|tapestry|realm|testament|transformative|cutting-edge|pivotal|paramount)\b/i.test(
        text
      ),
      'AI-slop word in How-it-works copy'
    ).toBe(false);
  });
});
