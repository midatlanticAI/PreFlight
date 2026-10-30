// src/lib/probes/v05/adapters/python/py-deserialize-001-unsafe-load.js
//
// XL-001 adapter for Python. RX-based (no Python AST in-browser; the
// inventory's conservative RX variant is the browser-portable approach).
//
// Catches: pickle.load/loads, cPickle.load*, dill.load*, joblib.load,
// torch.load without weights_only=True, pandas.read_pickle, and yaml.load
// without a safe loader. New probe (no v0.4 ancestor) — legacy_finding_id_seed
// is null. Ships shadow + experimental for the Phase 1 soak.

import { pythonFiles, isPythonCommentLine } from '../../shared-detectors/python-scope.js';

const PROBE_NAME = 'Python Unsafe Deserialization';

// Deserialize calls that construct arbitrary objects from bytes.
const UNSAFE_CALL_RE =
  /\b(?:pickle|cPickle|_pickle)\.(?:load|loads)\s*\(|\bdill\.(?:load|loads)\s*\(|\bjoblib\.load\s*\(|\bpandas\.read_pickle\s*\(|\bpd\.read_pickle\s*\(/;

// torch.load is only unsafe when weights_only is NOT True. PyTorch 2.6 made
// weights_only=True the default, so flag only the explicit override.
const TORCH_LOAD_RE = /\btorch\.load\s*\(/;
const TORCH_WEIGHTS_FALSE_RE = /weights_only\s*=\s*False/;

// Mask strings and comments before inspecting arguments. Offsets/newlines are
// preserved; text mentioning a loader cannot become an exemption. This is a
// lexical check, not Python name resolution or a general Python parser.
function maskPythonText(content) {
  return content.replace(
    /#[^\n]*|"""[\s\S]*?(?:"""|$)|'''[\s\S]*?(?:'''|$)|"(?:\\[\s\S]|[^"\\])*"|'(?:\\[\s\S]|[^'\\])*'/g,
    (text) => text.replace(/[^\n]/g, text.startsWith('#') ? ' ' : '@')
  );
}

const SAFE_LOADER_RE = /^(?:yaml\s*\.\s*)?C?SafeLoader$/;

function unsafeYamlLines(content) {
  const code = maskPythonText(content);
  const unsafe = new Set();
  for (const call of code.matchAll(/\byaml\s*\.\s*load\s*\(/g)) {
    // Split only at the call's top-level commas. Nested calls/containers and
    // other calls on the same line must not supply this call's Loader.
    const args = [];
    let depth = 0;
    let start = call.index + call[0].length;
    for (let i = start; i < code.length; i++) {
      const ch = code[i];
      if (ch === ')' && depth === 0) {
        args.push(code.slice(start, i).trim());
        break;
      }
      if ('([{'.includes(ch)) depth++;
      else if (')]}'.includes(ch)) depth--;
      else if (ch === ',' && depth === 0) {
        args.push(code.slice(start, i).trim());
        start = i + 1;
      }
    }
    const keyword = args.find((arg) => /^Loader\s*=/.test(arg));
    const loader = keyword ? keyword.replace(/^Loader\s*=\s*/, '') : args[1];
    // **kwargs can override a positional loader; don't infer safety through
    // dynamic arguments, aliases, constructors, attributes, or lookalike names.
    if (loader && SAFE_LOADER_RE.test(loader) && !args.some((arg) => /^\*\*/.test(arg))) {
      continue;
    }
    unsafe.add(code.slice(0, call.index).split('\n').length - 1);
  }
  return unsafe;
}

export const PY_DESERIALIZE_001 = {
  probe_id: 'PY-DESERIALIZE-001',
  xl_family: 'XL-001',
  language: 'python',
  name: PROBE_NAME,
  category: 'security',
  severity: 'critical',
  confidence: 'medium',
  cwe: 'CWE-502',
  owasp_web: 'A08',
  owasp_llm: null,
  detector: 'rx',
  scope: '**/*.py',
  what_it_catches:
    'pickle / cPickle / dill / joblib / pandas.read_pickle on any input, torch.load with weights_only=False, and yaml.load without a safe loader. Each constructs arbitrary Python objects from bytes.',
  why_ai_v05:
    'AI tools confuse pickle with JSON when asked to "serialize this object," and ML tutorials use pickle for model artifacts so the assistant generalizes the pattern to request bodies.',
  vibe_v05:
    '"Save object, load object." No trust boundary between bytes I wrote and bytes a request sent.',
  detection_approach:
    'RX per line: pickle/cPickle/dill .load(s), joblib.load, pandas.read_pickle; torch.load with weights_only=False; yaml.load with no explicit positional or keyword SafeLoader/CSafeLoader in that call.',
  fp_gates_v05: [
    'comment-only lines (teaching examples)',
    'torch.load already passing weights_only=True (or relying on the 2.6+ default with no override)',
    'yaml.load with an explicit SafeLoader/CSafeLoader argument (bare or yaml-qualified)',
    'test files and the scanner self-source (handled by pythonFiles())',
  ],
  remediation:
    'Use JSON for data. For ML models use safetensors, or torch.load(path, weights_only=True). For YAML use yaml.safe_load(data). Never deserialize a request body with pickle.',
  autofix_v05: 'review-needed',
  fixtures_v05: {
    positive: 'src/lib/probes/v05/fixtures/PY-DESERIALIZE-001/positive.py',
    negative: 'src/lib/probes/v05/fixtures/PY-DESERIALIZE-001/negative.py',
  },
  known_incidents: 'CVE-2007-4559; CWE-502; PyTorch 2.6 weights_only default; HF safetensors push',
  ioc_bundle_ref: null,
  maturity: 'experimental',
  shadow: false,
  legacy_finding_id_seed: null,
  detect(files) {
    const findings = [];
    for (const f of pythonFiles(files)) {
      const lines = f.content.split('\n');
      const yamlUnsafe = unsafeYamlLines(f.content);
      lines.forEach((line, i) => {
        if (isPythonCommentLine(line)) return;
        let hit = null;
        if (UNSAFE_CALL_RE.test(line)) {
          hit = 'pickle/dill/joblib/read_pickle deserialization';
        } else if (TORCH_LOAD_RE.test(line) && TORCH_WEIGHTS_FALSE_RE.test(line)) {
          hit = 'torch.load with weights_only=False';
        } else if (yamlUnsafe.has(i)) {
          hit = 'yaml.load without a safe loader';
        }
        if (!hit) return;
        findings.push({
          id: `py-deser-${f.path}-${i}`,
          probe: PROBE_NAME,
          title: `Unsafe deserialization: ${hit}`,
          severity: 'critical',
          category: 'Security',
          cwe: 'CWE-502',
          file: f.path,
          line: i + 1,
          evidence: line.trim().slice(0, 200),
          remediation:
            'Use JSON for data, safetensors / torch.load(weights_only=True) for models, yaml.safe_load for YAML. Pickle on untrusted bytes is remote code execution.',
        });
      });
    }
    return findings;
  },
};
