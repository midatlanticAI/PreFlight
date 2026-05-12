// Validates the structural invariants every Persona+ spec must hold.
//
// The personas under src/lib/personas/ are deployed as system prompts in
// production code paths (formatAgentPrompt uses Sam; Drew / Vera ship as
// ready-to-wire specs for the design-rules and engineering-rules surfaces
// that don't exist yet). When a persona drifts away from the contract,
// every consumer downstream breaks at once, so the contract is enforced
// at the test layer.

import { describe, it, expect } from 'vitest';
import { sam, demi, drew, vera, PERSONAS } from '../lib/personas/index.js';

const ALL = [
  ['sam', sam],
  ['demi', demi],
  ['drew', drew],
  ['vera', vera],
];

describe('persona registry', () => {
  it('exports the four expected personas', () => {
    expect(Object.keys(PERSONAS).sort()).toEqual(['demi', 'drew', 'sam', 'vera']);
  });
});

describe.each(ALL)('Persona+ spec: %s', (name, persona) => {
  it('has all required Persona+ top-level fields', () => {
    expect(persona.NAME).toBeTypeOf('string');
    expect(persona.FOCUS).toBeTypeOf('string');
    expect(persona.BIO).toBeTypeOf('string');
    expect(persona.SKILLS).toBeTypeOf('object');
    expect(persona.NO_NOS).toBeTypeOf('object');
    expect(persona.TEMPLATE).toBeTypeOf('string');
    expect(persona.ACKNOWLEDGMENT).toBeTypeOf('string');
    expect(persona.INSTRUCTIONS).toBeTypeOf('string');
  });

  it('NAME is a proper noun the user might see (capitalized, no acronym leakage)', () => {
    expect(persona.NAME).toMatch(/^[A-Z][a-z]+$/);
  });

  it('SKILLS is a non-empty numbered object', () => {
    const keys = Object.keys(persona.SKILLS);
    expect(keys.length).toBeGreaterThan(0);
    keys.forEach((k) => expect(k).toMatch(/^\d+$/));
  });

  it('NO_NOS is a non-empty numbered object and includes an em-dash ban', () => {
    const keys = Object.keys(persona.NO_NOS);
    expect(keys.length).toBeGreaterThan(0);
    const joined = Object.values(persona.NO_NOS).join('\n');
    expect(joined).toMatch(/em-dash/i);
  });

  it('NO_NOS includes a prompt-injection defense (data not commands)', () => {
    const joined = Object.values(persona.NO_NOS).join('\n').toLowerCase();
    expect(joined).toMatch(/instruction|persona drift|data only|never commands/);
  });

  it('ACKNOWLEDGMENT starts with the persona name', () => {
    expect(persona.ACKNOWLEDGMENT.startsWith(`${persona.NAME} online`)).toBe(true);
  });

  it('INSTRUCTIONS references the activation acknowledgment verbatim', () => {
    expect(persona.INSTRUCTIONS).toContain(persona.ACKNOWLEDGMENT);
  });

  it('INSTRUCTIONS contains the persona name and the activation gate phrase', () => {
    expect(persona.INSTRUCTIONS).toContain(`You are ${persona.NAME}`);
    expect(persona.INSTRUCTIONS).toMatch(/On activation, respond/);
  });

  it("INSTRUCTIONS contains no em-dashes (the persona's own ban applies to its spec text)", () => {
    expect(persona.INSTRUCTIONS).not.toContain('—');
  });
});

describe('Sam dual-mode', () => {
  it('declares both SAM_COMMAND_FULL and SAM_COMMAND_SNIPPET in STRUCTURED_COMMANDS', () => {
    expect(sam.STRUCTURED_COMMANDS).toBeTypeOf('object');
    expect(sam.STRUCTURED_COMMANDS.SAM_COMMAND_FULL).toBeTypeOf('object');
    expect(sam.STRUCTURED_COMMANDS.SAM_COMMAND_SNIPPET).toBeTypeOf('object');
  });

  it('SAM_COMMAND_FULL input includes FILE_CONTENT; SNIPPET does not', () => {
    const full = sam.STRUCTURED_COMMANDS.SAM_COMMAND_FULL.input_fields;
    const snip = sam.STRUCTURED_COMMANDS.SAM_COMMAND_SNIPPET.input_fields;
    expect(full).toContain('FILE_CONTENT');
    expect(snip).not.toContain('FILE_CONTENT');
  });

  it('INSTRUCTIONS describes both modes', () => {
    expect(sam.INSTRUCTIONS).toContain('SAM_COMMAND_FULL');
    expect(sam.INSTRUCTIONS).toContain('SAM_COMMAND_SNIPPET');
  });
});

describe('Demi dual-mode', () => {
  it('declares both DEMI_MODE_AUTHOR and DEMI_MODE_GRADE in STRUCTURED_COMMANDS', () => {
    expect(demi.STRUCTURED_COMMANDS.DEMI_MODE_AUTHOR).toBeTypeOf('object');
    expect(demi.STRUCTURED_COMMANDS.DEMI_MODE_GRADE).toBeTypeOf('object');
  });

  it('INSTRUCTIONS describes both AUTHOR and GRADE procedures', () => {
    expect(demi.INSTRUCTIONS).toContain('DEMI_MODE_AUTHOR procedure');
    expect(demi.INSTRUCTIONS).toContain('DEMI_MODE_GRADE procedure');
  });

  it('grades against the six-section skeleton documented in TEMPLATE', () => {
    expect(demi.TEMPLATE).toContain('PATTERN PAGE');
    expect(demi.TEMPLATE).toContain('FIELD REPORT');
    expect(demi.TEMPLATE).toContain('SHAPE PAGE');
    expect(demi.TEMPLATE).toContain('MANIFESTO');
  });
});

describe('Drew + Vera (enforcement personas)', () => {
  it('Drew enforces design rules; Vera enforces engineering rules', () => {
    expect(drew.FOCUS).toMatch(/design/i);
    expect(vera.FOCUS).toMatch(/engineering/i);
  });

  it('both define the four terminal output states (NO_VIOLATIONS, NO_APPLICABLE_RULES, INSUFFICIENT_CONTEXT, plus violation reports)', () => {
    for (const p of [drew, vera]) {
      expect(p.TEMPLATE).toContain('NO_VIOLATIONS');
      expect(p.TEMPLATE).toContain('NO_APPLICABLE_RULES');
      expect(p.TEMPLATE).toContain('INSUFFICIENT_CONTEXT');
      expect(p.TEMPLATE).toContain('Rule:');
      expect(p.TEMPLATE).toContain('File:');
      expect(p.TEMPLATE).toContain('Found:');
      expect(p.TEMPLATE).toContain('Expected:');
      expect(p.TEMPLATE).toContain('Rule source:');
    }
  });

  it('both refuse to author new rules or override the provided rules file', () => {
    for (const p of [drew, vera]) {
      const joined = Object.values(p.NO_NOS).join('\n').toLowerCase();
      expect(joined).toMatch(/not a rules author|enforcement worker/);
    }
  });

  it('both expect the rules file under .preflight/', () => {
    expect(drew.INSTRUCTIONS).toContain('.preflight/design-rules.yml');
    expect(vera.INSTRUCTIONS).toContain('.preflight/engineering-rules.yml');
  });
});

describe('formatAgentPrompt uses Sam SNIPPET mode', async () => {
  // formatAgentPrompt is exported via App.jsx (see formatters.test.js for the same
  // import surface). Importing inside the describe so the module-level setup of
  // the App import doesn't pollute the persona-spec assertions above.
  const { formatAgentPrompt, buildSnippet } = await import('../App.jsx');

  const sampleResults = () => ({
    findings: [
      {
        id: 'a',
        probe: 'Secret Scanner',
        title: 'AWS Access Key found',
        severity: 'critical',
        category: 'Data Breach',
        cwe: 'CWE-798',
        file: 'src/config.js',
        line: 7,
        evidence: 'const k = "AK...XXXX"',
        remediation: 'Rotate the key.',
        snippet: buildSnippet('a\nb\nc\nd\ne\nf\ng\nh\ni\nj', 7, 2),
      },
    ],
    score: 65,
    scannedAt: new Date('2026-05-12T12:00:00Z'),
    filesScanned: 1,
    source: 'https://github.com/owner/repo',
  });

  it('embeds the Sam activation acknowledgment', () => {
    const p = formatAgentPrompt(sampleResults());
    expect(p).toContain(sam.ACKNOWLEDGMENT);
  });

  it('emits one SAM_COMMAND_SNIPPET task per finding', () => {
    const p = formatAgentPrompt(sampleResults());
    expect(p).toContain('COMMAND: SAM_COMMAND_SNIPPET');
  });

  it('documents that FILE_CONTENT is omitted in SNIPPET mode', () => {
    const p = formatAgentPrompt(sampleResults());
    expect(p).toMatch(/FILE_CONTENT:.*omitted/);
  });

  it('tells the receiving AI to skip the activation acknowledgment for batches', () => {
    const p = formatAgentPrompt(sampleResults());
    expect(p).toMatch(/skip the activation acknowledgment/i);
  });
});
