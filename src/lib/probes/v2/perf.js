// src/lib/probes/v2/perf.js
//
// F6: Performance hazards (docs/preflight-v2-spec.md §F6, 15-probe roster).
// The bundle and layout costs AI code pays without noticing: whole libraries
// imported for one helper, deprecated heavyweights in new code, images with
// no reserved box shifting the page under the reader's finger.
//
// Severity ceiling: MEDIUM (health axis).
//
// Roster entries deliberately not built, with reasons:
//   sync_heavy_work_in_render / layout_thrash_patterns /
//   json_parse_huge_payload — "heavy" is a runtime quantity; a static scan
//       flagging arbitrary loops as heavy would be guessing.
//   large_list_no_virtualization / image_no_lazy_below_fold /
//   image_no_modern_format — need render geometry and asset inventory.
//   useMemo_empty_deps / useMemo_unstable_deps / useCallback_over_use —
//       memoization judgment calls; React's own guidance is "profile
//       first", and a probe should not out-opinion the profiler.
//   context_value_re_render_cascade — owned by React Hygiene's inline
//       Provider-value check.
//   large_initial_useState_no_lazy_init — needs the value's cost, a
//       runtime fact.

import { isTestFile, isScannerSelfSource } from '../../file-filter.js';
import { maskCommentsForPath } from '../_internal/masking.js';

export const PERF_FILE_RE = /\.(?:[jt]sx?|mjs|cjs|html)$/i;

// Libraries whose default import drags the whole package into the bundle
// when a scoped import gets the same helper for a fraction of the size.
export const PERF_FULL_IMPORT_LIBS = new Set(['lodash', 'underscore', 'ramda', 'date-fns', 'rxjs']);

const finding = (o) => ({
  probe: 'Performance Hazards',
  category: 'Performance',
  severity: 'medium',
  cwe: 'CWE-1050',
  ...o,
});

export function probePerfHazards(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!PERF_FILE_RE.test(file.path)) return;
    const content = file.content || '';
    if (!content.trim()) return;
    if (!/<img|import|require\s*\(|document\.write|moment/.test(content)) return;
    const code = maskCommentsForPath(file.path, content);
    const codeLines = code.split('\n');
    const rawLines = content.split('\n');
    const push = (i, o) =>
      findings.push(
        finding({
          file: file.path,
          line: i + 1,
          evidence: (rawLines[i] ?? '').trim().slice(0, 160),
          ...o,
        })
      );

    codeLines.forEach((line, i) => {
      // <img> with no reserved box: the page reflows when it loads (CLS).
      // Gate-1: case-sensitive in JSX — a capitalized <Img> is a component
      // (styled-components' standard name), not the DOM element.
      const imgTagRe = /\.html?$/i.test(file.path) ? /<img\b/i : /<img\b/;
      if (imgTagRe.test(line)) {
        const tag = codeLines.slice(i, Math.min(codeLines.length, i + 3)).join(' ');
        const sized = /\bwidth\s*[==:{]/i.test(tag) && /\bheight\s*[=:{]/i.test(tag);
        const hasFill = /\bfill\b/.test(tag) || /aspect-?ratio/i.test(tag);
        // Gate-1: a className/style/css-prop-styled img is sized by its
        // stylesheet — the box is reserved in CSS the per-file scan cannot
        // read, so only the literally unstyled img is the mechanical call.
        const styledElsewhere = /className=|class=|style=|css=/.test(tag);
        if (!sized && !hasFill && !styledElsewhere) {
          push(i, {
            id: `perf-img-nosize-${file.path}-${i}`,
            title: 'Image with no width and height',
            severity: 'medium',
            cwe: 'CWE-1050',
            remediation:
              'Until the file arrives the browser reserves zero height, then the whole page below jumps when it does — that shift is the thing users misclick through, and it is scored directly as CLS. Set width and height (or aspect-ratio in CSS); the box is reserved before the bytes arrive.',
          });
        }
      }
      // Whole-library default imports.
      // Gate-2 (C26): require('lodash') ships the same whole library the
      // import spelling does.
      const im = line.match(
        /import\s+(?:_|\w+)\s+from\s+['"](lodash|underscore|ramda)['"]|import\s*\*\s*as\s+\w+\s+from\s+['"](lodash|underscore|ramda|date-fns|rxjs)['"]|require\s*\(\s*['"](lodash|underscore|ramda)['"]\s*\)/
      );
      if (im) {
        const lib = im[1] || im[2] || im[3];
        push(i, {
          id: `perf-full-import-${file.path}-${i}`,
          title: `Whole ${lib} imported`,
          severity: 'medium',
          remediation: `The default import ships the entire library to pay for the one or two helpers used. Import the helpers directly (import debounce from '${lib}/debounce' or the scoped named import) and the bundler drops the rest.`,
        });
      }
      // moment in new code: officially in maintenance mode, famously heavy.
      // Gate-2 (C32): subpath imports (moment/locale/de, moment/min/…) are
      // the same dependency.
      if (
        /import\s+[\w{*]\S*\s.*from\s+['"]moment(?:\/[^'"]*)?['"]|import\s+['"]moment\/[^'"]*['"]|require\s*\(\s*['"]moment(?:\/[^'"]*)?['"]\s*\)/.test(
          line
        )
      ) {
        push(i, {
          id: `perf-moment-${file.path}-${i}`,
          title: 'moment.js imported in new code',
          severity: 'low',
          remediation:
            "Moment's own maintainers put it in maintenance mode and point new projects elsewhere; it is large, mutable, and drags locale data along. Date.now/Intl cover the basics; date-fns or dayjs cover the rest at a fraction of the size.",
        });
      }
      // document.write blocks parsing and can wipe the document.
      if (/document\.write\s*\(/.test(line)) {
        push(i, {
          id: `perf-docwrite-${file.path}-${i}`,
          title: 'document.write call',
          severity: 'medium',
          remediation:
            'document.write blocks the parser while it runs, and called after load it replaces the whole document with its argument. Build nodes and append them, or set element.textContent / insertAdjacentHTML on a container you own.',
        });
      }
    });
  });
  return findings;
}
