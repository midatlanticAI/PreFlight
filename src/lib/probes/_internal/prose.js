// src/lib/probes/_internal/prose.js
//
// Telling English apart from source.
//
// Two checks kept reporting documentation as a defect, for the same reason:
// both asked "does this text contain a code keyword" and English contains code
// keywords constantly. `if`, `for`, `return`, `class`, `export` and `in` are
// ordinary words.
//
//   - The commented-out-code check read every file-header block as a run of
//     disabled code. A line like "does any FILE_INCLUDE regex match, no
//     FILE_EXCLUDE hit" counts as code because it contains `does` inside a
//     word boundary scan, and a well-documented file scored worse than an
//     undocumented one.
//   - The string-literal checks read remediation copy as the thing it
//     describes. "Same identifier for user AND password is the strongest
//     signal" is a sentence about default credentials, not a credential.
//
// The discriminator that actually works is grammar, not vocabulary. English
// prose is mostly function words — articles, prepositions, auxiliaries — and
// source code has almost none of them, because code names things and English
// relates them. A line with five or more words where a fifth of them are
// function words is a sentence. `const persistConfig = { key: 'auth' }` has
// none.

// Closed-class English words. Deliberately excludes anything that reads
// naturally as an identifier (`type`, `name`, `value`, `data`, `key`) and
// anything a code line uses structurally often enough to skew the ratio.
const FUNCTION_WORDS =
  /\b(?:a|an|the|is|are|was|were|be|been|being|am|that|which|who|whom|whose|this|these|those|and|or|but|nor|not|with|without|from|into|onto|than|then|when|where|what|why|how|it|its|you|your|yours|we|us|our|they|them|their|he|she|his|her|as|at|by|on|to|of|in|for|if|so|do|does|did|done|no|any|all|every|each|only|just|still|because|since|while|until|never|always|often|would|should|could|can|cannot|may|might|must|will|shall|have|has|had|there|here|about|after|before|between|through|over|under|above|below|again|same|other|another|more|most|less|least|own|both|either|neither|too|very|much|many|some|such|per|via)\b/gi;

// Punctuation that is structural in source and rare in a sentence.
const CODE_PUNCT = /[;{}[\]()<>=+*/\\|&^~`$#@]/g;

// Shapes that settle it outright: whatever the word ratio says, this is code.
const DECIDING_CODE_SHAPES = [
  /[;{]\s*$/, // statement or block terminator
  /=>/, // arrow function
  /\b(?:function|=>)\s*\(/, // function expression
  /^\s*(?:const|let|var)\s+[\w$]+\s*=/, // declaration with initialiser
  /^\s*(?:import|export)\s/, // module syntax
  /^\s*(?:if|for|while|switch|catch)\s*\(/, // control flow with a condition
  /^\s*(?:return|throw|await)\s+[\w$[({'"`]/, // statement keyword + operand
  /^\s*[\w$.]+\s*[:=]\s*(?:\{|\[|function|async|\()/, // property bound to a structure
];

/**
 * True when `text` reads as an English sentence rather than source code.
 *
 * Conservative by design: it answers "is this definitely prose", so anything
 * ambiguous comes back false and the caller's existing logic still runs. That
 * keeps a wrong answer here from silencing a real finding.
 *
 * @param {string} text
 * @returns {boolean}
 */
export function looksLikeProse(text) {
  const s = String(text ?? '').trim();
  if (!s) return false;

  // A decisive code shape ends it. A sentence does not close a block.
  for (const re of DECIDING_CODE_SHAPES) {
    if (re.test(s)) return false;
  }

  const words = s.split(/\s+/).filter(Boolean);
  // Too short to read grammar off. Three words is a label ("eval() usage
  // detected"), not a sentence, and guessing on it costs more than it saves.
  if (words.length < 5) return false;

  const functionWords = (s.match(FUNCTION_WORDS) || []).length;
  const ratio = functionWords / words.length;
  if (ratio < 0.18) return false;

  // Sentences are mostly letters and spaces. A line dense in brackets and
  // operators is code that happens to contain English.
  const punct = (s.match(CODE_PUNCT) || []).length;
  if (punct / s.length > 0.08) return false;

  // Identifier-shaped tokens (camelCase, snake_case, dotted paths) are the
  // vocabulary of code. A couple inside a sentence is normal — documentation
  // names what it documents — but a majority means this is a code line.
  const identifierish = words.filter((w) =>
    /^[\w$]*(?:[a-z][A-Z]|_[a-z]|\.[a-z$_])[\w$.]*$/.test(w)
  ).length;
  if (identifierish / words.length > 0.4) return false;

  return true;
}

/**
 * True when `line` is carrying a string literal whose contents read as prose.
 *
 * The cheap form of the guard below, for probes that already iterate per line
 * and have no byte offset to hand. It answers the common shape directly: a
 * remediation or teaching string, alone on its line, quoting the pattern the
 * probe is looking for.
 *
 * @param {string} line
 */
export function lineIsProseString(line) {
  const s = String(line ?? '');
  const m = s.match(/(['"`])([\s\S]*)\1/); // first quote to last matching quote
  if (!m) return false;
  return looksLikeProse(m[2]);
}

/**
 * True when the match at `index` sits inside a string literal whose contents
 * read as prose.
 *
 * This is the guard for checks that MUST see string values — a connection
 * string, a JWT `alg` value, a URL carrying a token — and therefore cannot
 * simply run against the strings-blanked view. They still need to ignore the
 * sentence in a remediation string that quotes the very pattern they hunt.
 *
 * @param {string} content full file text
 * @param {number} index   offset of the match within `content`
 */
export function isMatchInsideProseString(content, index) {
  if (typeof content !== 'string' || !Number.isInteger(index) || index < 0) return false;
  const literal = enclosingStringLiteral(content, index);
  if (literal === null) return false;
  return looksLikeProse(literal);
}

// Walk back from `index` to find the string literal containing it, if any.
// Returns the literal's interior text, or null when the position is code.
//
// Scanning from the start of the line is not enough (template literals and
// concatenated copy span lines) so this walks from the start of the file,
// which is cheap next to the regex work the callers already do.
function enclosingStringLiteral(content, index) {
  let i = 0;
  const len = Math.min(content.length, index + 1_000_000);
  while (i < len && i <= index) {
    const c = content[i];
    const c2 = content[i + 1];
    // Skip comments so a quote inside one does not open a literal.
    if (c === '/' && c2 === '/') {
      const nl = content.indexOf('\n', i);
      if (nl === -1 || nl > index) return null;
      i = nl + 1;
      continue;
    }
    if (c === '/' && c2 === '*') {
      const end = content.indexOf('*/', i + 2);
      if (end === -1 || end > index) return null;
      i = end + 2;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') {
      const quote = c;
      let j = i + 1;
      while (j < content.length) {
        if (content[j] === '\\') {
          j += 2;
          continue;
        }
        if (content[j] === quote) break;
        if (quote !== '`' && content[j] === '\n') break; // unterminated
        j++;
      }
      if (index > i && index < j) return content.slice(i + 1, j);
      if (j >= content.length) return null;
      i = (content[j] === quote ? j : j) + 1;
      continue;
    }
    i++;
  }
  return null;
}
