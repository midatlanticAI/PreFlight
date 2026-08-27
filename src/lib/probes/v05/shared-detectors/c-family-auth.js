// src/lib/probes/v05/shared-detectors/c-family-auth.js
//
// XL-013 detection shared by the C and C++ adapters. Both languages verify
// tokens through the same two layers (a JWT library, then OpenSSL or mbedTLS
// underneath), so the signature-checking rules are identical and only the
// library-specific rules differ.
//
// Three things here are NOT in the other language adapters, because an
// adversarial pass proved each one produces false positives on correct code:
//
// 1. BLOCK COMMENTS. isCFamilyCommentLine() is a per-line SHAPE test: it
//    matches a line that STARTS with // or * or /*. An interior line of a
//    /* ... */ block that starts with code is not caught, and commenting out a
//    crypto call while debugging is exactly what people do. State has to be
//    carried across the loop.
//
// 2. LINE CONTINUATION. clang-format wraps long calls, so
//        const int rc =
//            EVP_DigestVerifyFinal(ctx, sig, len);
//    puts the call at the start of its own line and it reads as a discarded
//    return value when the value is in fact used. If the previous line ends in
//    an operator or an open bracket, this line is a continuation.
//
// 3. BOUNDED ARGUMENTS. `[^;]*` happily matches a `)`, so a pattern meant to
//    read one call's arguments runs past its closing paren and binds a later,
//    unrelated comparison on the same line. Correct code of the form
//        if (EVP_DigestVerifyFinal(...) != 1 || strcmp(a, b) != 0)
//    matched a "compared against the wrong value" rule via strcmp's `!= 0`.
//    Every argument list below is bounded so it cannot cross an unbalanced
//    paren.

// OpenSSL documents EVP_DigestVerifyFinal as returning 1 for success and "any
// other value" for failure, so `!= 1` is the only correct test. Treating it as
// a POSIX-style status (== 0, >= 0, != -1) accepts forged signatures.
export const C_VERIFY_WRONG_COMPARE_RE =
  /\bEVP_DigestVerify(?:Final)?\s*\((?:[^;()]|\([^;()]*\))*\)\s*(?:!=\s*-\s*1|>=\s*0|>\s*-\s*1|[!=]=\s*0)/;

// The verification call as a bare statement: the return value, which IS the
// verification result, is thrown away. The lookahead rejects a function
// prototype, whose first argument is `type name`.
export const C_VERIFY_DISCARDED_RE =
  /^\s*(?:EVP_DigestVerify(?:Final)?|mbedtls_pk_verify(?:_ext|_restartable)?)\s*\((?!\s*(?:const\s+|struct\s+|unsigned\s+|volatile\s+)*\w+\s+\*?\s*\w+\s*[,)])(?:[^;()]|\([^;()]*\))*\)\s*;/;

// A signature or MAC compared with a non-constant-time function. Both of the
// first two arguments must carry a credential noun, and an ordering comparison
// is rejected, because `memcmp(a->signature, b->signature, n) < 0` is a qsort
// comparator and `memcmp(hdr->signature, ZIP_LOCAL_SIG, 4)` is a file-format
// magic check. `signature` is the idiomatic C name for both.
export const C_TIMING_COMPARE_RE =
  /\b(?:memcmp|strncmp|strcmp)\s*\((?=(?:[^;()]|\([^;()]*\))*(?:signature|hmac))\s*(?=(?:[^;(),]|\(\s*\))*(?:signature|hmac|expected|computed|provided|received|calculated|supplied|derived))(?:[^;(),]|\(\s*\))*,\s*(?=(?:[^;(),]|\(\s*\))*(?:signature|hmac|expected|computed|provided|received|calculated|supplied|derived))(?:[^;(),]|\(\s*\))*(?:,\s*(?:[^;(),]|\(\s*\))*)?\)(?!\s*[<>])/i;

// A wrapped continuation: the previous line ended mid-expression, so this
// line's leading call is not a statement of its own.
const CONTINUATION_RE = /(?:[=?:,(&|]|&&|\|\||\breturn\b)\s*$/;

/**
 * Walk a C-family file line by line with block-comment state carried across
 * lines, calling back only for lines that are real code.
 *
 * @param {string} content
 * @param {(line: string, index: number, prevCodeLine: string) => void} onCodeLine
 */
export function forEachCFamilyCodeLine(content, onCodeLine) {
  const lines = String(content || '').split('\n');
  let inBlock = false;
  let prevCodeLine = '';
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    let line = raw;

    if (inBlock) {
      const end = line.indexOf('*/');
      if (end === -1) continue; // still inside the comment
      inBlock = false;
      line = line.slice(end + 2);
    }

    // Strip complete /* ... */ spans, then open a block if one is left hanging.
    line = line.replace(/\/\*(?:(?!\*\/)[\s\S])*\*\//g, ' ');
    const open = line.indexOf('/*');
    if (open !== -1) {
      inBlock = true;
      line = line.slice(0, open);
    }

    // Line comments.
    const slashes = line.indexOf('//');
    if (slashes !== -1) line = line.slice(0, slashes);

    if (!line.trim()) continue;
    onCodeLine(line, i, prevCodeLine);
    prevCodeLine = line;
  }
}

/**
 * Is this line the tail of a wrapped expression rather than its own statement?
 * @param {string} prevCodeLine
 * @returns {boolean}
 */
export function isContinuationOf(prevCodeLine) {
  return CONTINUATION_RE.test(prevCodeLine || '');
}
