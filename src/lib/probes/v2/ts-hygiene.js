// src/lib/probes/v2/ts-hygiene.js
//
// F5: TypeScript hygiene (docs/preflight-v2-spec.md §F5, 15-probe roster).
// The compiler is the one reviewer AI code always has; these are the shapes
// that fire the reviewer. @ts-ignore with no reason, `as any`, the
// double-cast laundering trick, strict mode switched off at the root.
//
// Severity ceiling: MEDIUM (health axis: this family is about giving up
// type safety, which enables defects rather than being one).
//
// Roster entries deliberately not built, with reasons:
//   implicit_any_returns / type_predicate_that_does_not_narrow /
//   discriminated_union_overlaps / generic_constraint_too_loose /
//   unused_generic_param / type_narrowing_lost_after_await — each needs the
//   type checker itself; a line scan asserting type facts would be guessing
//   with a confident face.
//   enum_used_as_string_literal — a style choice with no defect boundary.

import { isTestFile, isScannerSelfSource } from '../../file-filter.js';
import { maskCommentsForPath, maskCommentsOnly } from '../_internal/masking.js';

export const TS_FILE_RE = /\.(?:ts|tsx|mts|cts)$/i;

const finding = (o) => ({
  probe: 'TypeScript Hygiene',
  category: 'Code Correctness',
  severity: 'medium',
  cwe: 'CWE-1164',
  ...o,
});

export function probeTsHygiene(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    // Gate-1: shared mock factories live in test-utils/ / test-helpers/ and
    // are imported only by exempted tests; the same policy that exempts
    // *.test.ts covers their home directory.
    if (/(^|\/)(?:test-?utils?|test-?helpers?|testing)\//i.test(file.path)) return;

    // tsconfig checks read the config file itself.
    if (/(^|\/)tsconfig(?:\.\w+)?\.json$/i.test(file.path)) {
      const content = file.content || '';
      // tsconfig is JSONC: a comment recalling the old setting ("strict":
      // false was the old setting) fired on a config whose strict is true
      // (Gate-3 G11). Decide on the comment-blind view, quote the raw line.
      const rawLines = content.split('\n');
      const lines = maskCommentsOnly(content).split('\n');
      const flag = (re, title, remediation) => {
        const i = lines.findIndex((l) => re.test(l));
        if (i === -1) return;
        findings.push(
          finding({
            id: `ts-config-${title.replace(/\W+/g, '-').toLowerCase()}-${file.path}`,
            title,
            severity: 'medium',
            file: file.path,
            line: i + 1,
            evidence: (rawLines[i] ?? '').trim().slice(0, 160),
            remediation,
          })
        );
      };
      flag(
        /"strict"\s*:\s*false/,
        'tsconfig strict mode is off',
        'strict: false switches off the checks that catch null derefs and implicit anys — most of the reason to use TypeScript. Turn strict on; if the errors flood, fix them file by file rather than keeping the checker blind everywhere.'
      );
      flag(
        /"noImplicitAny"\s*:\s*false/,
        'tsconfig allows implicit any',
        'Every unannotated parameter silently becomes any, and any spreads through everything it touches. Remove noImplicitAny: false (strict mode covers it) and annotate the parameters the checker then points at.'
      );
      return;
    }

    if (!TS_FILE_RE.test(file.path)) return;
    const content = file.content || '';
    if (!content.trim()) return;
    // Gate-3 G10: the gate did not carry the non-null-chain trigger, so
    // `u?.name!` at the end of an expression could never be reached.
    if (!/@ts-|as\s+any|as\s+unknown|!\.|\?\.\w+!/.test(content)) return;
    // Directives live in comments, so this family reads the RAW lines for
    // the @ts-* checks (the directive IS a comment) and the masked view for
    // the cast checks (a cast in a comment is documentation).
    const rawLines = content.split('\n');
    const codeLines = maskCommentsForPath(file.path, content).split('\n');
    const push = (i, o) =>
      findings.push(
        finding({
          file: file.path,
          line: i + 1,
          evidence: (rawLines[i] ?? '').trim().slice(0, 160),
          ...o,
        })
      );

    rawLines.forEach((raw, i) => {
      // @ts-nocheck: the whole file opts out of the compiler.
      if (/^\s*\/\/\s*@ts-nocheck\b/.test(raw)) {
        push(i, {
          id: `ts-nocheck-${file.path}-${i}`,
          title: '@ts-nocheck disables checking for the whole file',
          severity: 'medium',
          remediation:
            'Every type error in this file is now invisible, including the ones added next month. Delete the directive, run tsc, and fix what it reports — or at minimum shrink the opt-out to specific lines with commented @ts-expect-error.',
        });
      }
      // @ts-ignore / @ts-expect-error with no reason after it. Gate-2
      // (C23): the block-comment spelling (`/* @ts-ignore */`) suppresses
      // exactly the same way and was invisible to the line-comment match.
      const dm = raw.match(/(?:\/\/|\/\*)\s*@ts-(ignore|expect-error)\s*(.*)$/);
      if (
        dm &&
        dm[2]
          .replace(/\*\/.*$/, '')
          .trim()
          .replace(/^[-:]+\s*/, '').length < 8
      ) {
        push(i, {
          id: `ts-directive-${file.path}-${i}`,
          title: `@ts-${dm[1]} with no explanation`,
          severity: dm[1] === 'ignore' ? 'medium' : 'low',
          remediation:
            'The next reader cannot tell a known library quirk from a suppressed real bug. Say why on the same line (// @ts-expect-error TODO(#123): lib types lag v5), and prefer @ts-expect-error, which alerts you when the underlying error is fixed.',
        });
      }
    });

    codeLines.forEach((line, i) => {
      // as any: type checking ends at this expression.
      if (/\bas\s+any\b/.test(line)) {
        push(i, {
          id: `ts-as-any-${file.path}-${i}`,
          title: 'as any cast',
          severity: 'medium',
          remediation:
            'Everything reached through this value is unchecked from here on; the error surfaces later, at runtime, far from this line. Name the real type, or if it is genuinely unknown, cast to unknown and narrow with a type guard.',
        });
      }
      // as unknown as T: the laundering double-cast.
      if (/\bas\s+unknown\s+as\s+\w/.test(line)) {
        push(i, {
          id: `ts-double-cast-${file.path}-${i}`,
          title: 'as unknown as T double cast',
          severity: 'medium',
          remediation:
            'This tells the compiler "trust me twice": any value becomes any type with no check anywhere. If the shapes genuinely overlap, fix the types so a single assertion works; if they do not, the code is constructing the wrong value and this cast is hiding it.',
        });
      }
      // Non-null assertion stacked on optional chaining: "it might be
      // missing, but also it definitely is not".
      // Gate-1: the `)!.` branch is gone — asserting non-null on a call
      // result (document.getElementById('root')!) is the universal
      // bootstrap idiom with no ?. contradiction to teach.
      if (/\?\.\w+!/.test(line)) {
        push(i, {
          id: `ts-nonnull-chain-${file.path}-${i}`,
          title: 'Non-null assertion contradicts optional chaining',
          severity: 'low',
          remediation:
            'The ?. says the value may be absent; the ! then swears it is not. One of them is wrong, and if it is the !, this line throws exactly when the optional case happens. Handle the missing case, or assert once at the boundary where you actually know.',
        });
      }
    });
  });
  return findings;
}
