// src/lib/probes/v05/families/xl-006-hardcoded-secrets.js
//
// XL-006: Hardcoded Secrets and Policy Text. Pure metadata. Adapters
// reference via xl_family: "XL-006". The v0.4 Secret Scanner is the
// migration target for this family (Phase 2).

/** @type {import('../types.js').XLFamily} */
export const XL_006 = {
  xl_id: 'XL-006',
  name: 'Hardcoded Secrets and Policy Text',
  category: 'crypto',
  severity_default: 'high',
  cwe: 'CWE-798',
  owasp_web: 'A07',
  owasp_llm: ['LLM02', 'LLM07'],
  learn_more_slug: 'xl-hardcoded-secrets',
  why_ai_v05:
    'AI inlines a placeholder key to make the prototype run, and the placeholder gets forgotten before rotation. Lovable/Bolt/Replit emit pasted keys inline; Copilot autocompletes from clipboard.',
  vibe_v05:
    '"Just hard-code it for now, I will move it to an env var later." Later never arrives, and the prototype ships with the literal in source.',
  fp_gates_v05_shared: [
    '.example / .sample / .template files',
    'documentation and tutorial snippets',
    'obvious placeholder substrings (your_key, xxx, ..., EXAMPLE, changeme)',
    'env-loaded references (os.environ, getenv) rather than literals',
    'test fixtures with fake key shapes',
  ],
  autofix_v05: 'review-needed',
  fixtures_v05_pattern: {
    positive: 'a provider-key-shaped literal assigned in source or passed to a client ctor',
    negative: 'the key read from an environment variable / secret manager',
  },
};
