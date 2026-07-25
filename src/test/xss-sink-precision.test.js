// XSS sink precision. Verified-claim round 2026-07.
//
// The dangerouslySetInnerHTML check used to fire on any line mentioning the
// identifier, so `__html: ""`, `__html: "<b>ok</b>"` and, worst of all,
// `__html: DOMPurify.sanitize(x)` were all reported. The last one told authors
// to do the exact thing they had already done.
//
// The innerHTML assignment check had a literal-guard written as a negative
// lookahead after `\s*`. The `\s*` could backtrack to zero width, which put
// the lookahead on the space rather than the quote, so the guard inverted and
// `el.innerHTML = "static"` matched. The guard had never worked.
import { describe, it, expect } from 'vitest';
import { probeAuthWeakness } from '../lib/probes.js';

const f = (content, path = 'src/Component.jsx') => [{ path, content }];
const xss = (content, path) =>
  probeAuthWeakness(f(content, path)).filter((x) => /XSS|dangerouslySetInnerHTML/i.test(x.title));

describe('dangerouslySetInnerHTML: constants are not sinks', () => {
  it.each([
    ['empty string', '<div dangerouslySetInnerHTML={{ __html: "" }} />'],
    ['static markup', '<div dangerouslySetInnerHTML={{ __html: "<b>hello</b>" }} />'],
    ['single quotes', "<div dangerouslySetInnerHTML={{ __html: '<hr/>' }} />"],
    [
      'template literal with no substitution',
      '<div dangerouslySetInnerHTML={{ __html: `<hr/>` }} />',
    ],
  ])('does not flag %s', (_label, src) => {
    expect(xss(src)).toEqual([]);
  });

  it.each([
    ['DOMPurify', '<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(body) }} />'],
    ['sanitizeHtml', '<div dangerouslySetInnerHTML={{ __html: sanitizeHtml(body) }} />'],
    ['escapeHtml', '<div dangerouslySetInnerHTML={{ __html: escapeHtml(body) }} />'],
  ])('does not flag a value sanitized with %s', (_label, src) => {
    expect(xss(src)).toEqual([]);
  });

  it('flags a bare identifier', () => {
    expect(xss('<div dangerouslySetInnerHTML={{ __html: userInput }} />').length).toBeGreaterThan(
      0
    );
  });

  it('flags a property access', () => {
    expect(xss('<div dangerouslySetInnerHTML={{ __html: props.body }} />').length).toBeGreaterThan(
      0
    );
  });

  it('flags an interpolated template literal', () => {
    expect(
      xss('<div dangerouslySetInnerHTML={{ __html: `<p>${comment}</p>` }} />').length
    ).toBeGreaterThan(0);
  });

  it('flags an unsanitized call such as a markdown renderer', () => {
    expect(
      xss('<div dangerouslySetInnerHTML={{ __html: marked(body) }} />').length
    ).toBeGreaterThan(0);
  });

  it('handles the prettier-wrapped multi-line form', () => {
    const safe = ['<div', '  dangerouslySetInnerHTML={{', '    __html: "",', '  }}', '/>'].join(
      '\n'
    );
    expect(xss(safe)).toEqual([]);

    const tainted = [
      '<div',
      '  dangerouslySetInnerHTML={{',
      '    __html: userInput,',
      '  }}',
      '/>',
    ].join('\n');
    expect(xss(tainted).length).toBeGreaterThan(0);
  });
});

describe('innerHTML assignment: the literal guard actually works now', () => {
  it.each([
    ['double-quoted literal', 'el.innerHTML = "static";'],
    ['single-quoted literal', "el.innerHTML = 'static';"],
    ['no trailing semicolon', 'el.innerHTML = "static"'],
    ['outerHTML literal', 'el.outerHTML = "<hr/>";'],
  ])('does not flag %s', (_label, src) => {
    expect(xss(src, 'src/dom.js')).toEqual([]);
  });

  it.each([
    ['identifier', 'el.innerHTML = userInput;'],
    ['property access', 'el.innerHTML = data.body;'],
    ['interpolated template', 'el.innerHTML = `<p>${x}</p>`;'],
    ['concatenation', 'el.innerHTML = "<p>" + x + "</p>";'],
    ['append form', 'el.innerHTML += userInput;'],
  ])('flags %s', (_label, src) => {
    expect(xss(src, 'src/dom.js').length).toBeGreaterThan(0);
  });

  it('does not flag a sanitized assignment', () => {
    expect(xss('el.innerHTML = DOMPurify.sanitize(body);', 'src/dom.js')).toEqual([]);
  });
});
