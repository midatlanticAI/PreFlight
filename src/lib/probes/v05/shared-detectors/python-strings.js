// src/lib/probes/v05/shared-detectors/python-strings.js
//
// Two string-awareness helpers for Python line detectors.
//
// isPythonCommentLine() handles `#`. It does not handle the two ways Python
// text most often describes a dangerous call:
//
// 1. DOCSTRINGS. A triple-quoted block is prose spanning many lines, and its
//    interior lines carry no marker at all. A docstring that WARNS against
//    `options={"verify_signature": False}` is character-identical to the call
//    it warns about, so a detector without docstring state reports the warning.
//    This is the same problem as a C block comment, and it needs the same fix:
//    state carried across the loop rather than a per-line shape test.
//
// 2. SINGLE-LINE STRING ARGUMENTS. `help='pass options={"verify_signature":
//    False}'` is one line of ordinary code whose STRING happens to contain the
//    pattern. Docstring state cannot see it. What separates it from the real
//    call is that the match begins inside an unterminated quote.
//
// Neither is theoretical: both came out of an adversarial pass that wrote
// correct Python designed to trip the first draft of the XL-013 rules.

/**
 * Walk a Python file, skipping comment lines and the interior of triple-quoted
 * blocks, and hand back only lines that are code.
 *
 * Triple-quote tracking is deliberately simple: it toggles on an odd number of
 * a given triple-quote token on a line. That is correct for docstrings and for
 * ordinary multi-line strings, and it does not try to model nesting, which
 * Python does not allow for the same token anyway.
 *
 * @param {string} content
 * @param {(line: string, index: number) => void} onCodeLine
 */
export function forEachPythonCodeLine(content, onCodeLine) {
  const lines = String(content || '').split('\n');
  let openToken = null; // '"""' or "'''" while inside a block

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];

    if (openToken) {
      // Inside a triple-quoted block: look for its close, and only resume on
      // whatever follows the closing token on that same line.
      const end = raw.indexOf(openToken);
      if (end === -1) continue;
      const after = raw.slice(end + openToken.length);
      openToken = null;
      if (!after.trim()) continue;
      if (!isOpeningTriple(after)) onCodeLine(after, i);
      else openToken = openingTripleToken(after);
      continue;
    }

    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    if (isOpeningTriple(raw)) {
      // A line that opens a block: everything before the token is still code.
      const token = openingTripleToken(raw);
      const at = raw.indexOf(token);
      const before = raw.slice(0, at);
      openToken = token;
      if (before.trim()) onCodeLine(before, i);
      continue;
    }

    onCodeLine(raw, i);
  }
}

// Does this line leave a triple-quoted block open? An even count closes again.
function isOpeningTriple(line) {
  return openingTripleToken(line) !== null;
}

function openingTripleToken(line) {
  const dq = (line.match(/"""/g) || []).length;
  const sq = (line.match(/'''/g) || []).length;
  if (dq % 2 === 1 && sq % 2 === 1) {
    // Both left open on one line: the one that appears first wins.
    return line.indexOf('"""') < line.indexOf("'''") ? '"""' : "'''";
  }
  if (dq % 2 === 1) return '"""';
  if (sq % 2 === 1) return "'''";
  return null;
}

/**
 * Does the match at `index` begin inside a single-line string literal?
 *
 * Counts unescaped quotes of each kind before the match. An odd count means a
 * quote of that kind is still open, so the match is text rather than code.
 * Triple-quote tokens are removed first so they cannot skew the parity.
 *
 * @param {string} line
 * @param {number} index  offset where the match begins
 * @returns {boolean}
 */
export function isInsideStringLiteral(line, index) {
  if (typeof line !== 'string' || !(index > 0)) return false;
  const before = line.slice(0, index).replace(/"""|'''/g, '');
  let dq = 0;
  let sq = 0;
  for (let i = 0; i < before.length; i++) {
    const ch = before[i];
    if (ch === '\\') {
      i++; // skip the escaped character
      continue;
    }
    if (ch === '"') dq++;
    else if (ch === "'") sq++;
  }
  return dq % 2 === 1 || sq % 2 === 1;
}
