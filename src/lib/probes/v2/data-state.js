// src/lib/probes/v2/data-state.js
//
// F4: Data fetching and state management (docs/preflight-v2-spec.md §F4,
// 18-probe roster). The gap between "the data appears" and "the data is
// managed": duplicate fetches, fetches during render, polling with no
// backoff, state seeded from props and never updated again.
//
// Severity ceiling: MEDIUM (correctness/performance family, health axis).
//
// Roster entries deliberately not built, with reasons:
//   supabase_rls_missing_select_all (the spec anchor) — owned outright by
//       the existing Supabase RLS probe, which resolves policies and loops;
//       a second reader would double-fire the most sensitive check in the
//       registry.
//   fetch_no_cleanup / polling_no_stop_condition — owned by React Hygiene's
//       effect-cleanup family.
//   localStorage_no_try_catch — owned by Async Correctness (JSON.parse on
//       external input).
//   optimistic_update_no_rollback / stale_data_after_mutation /
//   swr_mutate_no_revalidate / zustand_action_not_returning_new_state —
//       need dataflow across renders; every static heuristic modeled was
//       FP-dominated.
//   redux_direct_mutation — immer made mutation the DOCUMENTED idiom inside
//       createSlice/createReducer; flagging assignment shape would mark the
//       official style guide wrong.
//   infinite_scroll_no_virtualization / polling_no_visibility_pause /
//   indexeddb_no_migration_plan — design judgments, not detectable defects.

import { isTestFile, isScannerSelfSource } from '../../file-filter.js';
import { maskCommentsForPath } from '../_internal/masking.js';
import { lineIndex } from './line-index.js';

export const DATA_FILE_RE = /\.(?:[jt]sx?|mjs|cjs)$/i;

const finding = (o) => ({
  probe: 'Data & State',
  category: 'Code Correctness',
  severity: 'medium',
  cwe: 'CWE-1088',
  ...o,
});

export function probeDataState(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!DATA_FILE_RE.test(file.path)) return;
    const content = file.content || '';
    if (!content.trim()) return;
    if (!/\bfetch\s*\(|useQuery|useState|setInterval/.test(content)) return;
    const code = maskCommentsForPath(file.path, content);
    const codeLines = code.split('\n');
    const rawLines = content.split('\n');
    const push = (line, o) =>
      findings.push(
        finding({
          file: file.path,
          line,
          evidence: (rawLines[line - 1] ?? '').trim().slice(0, 160),
          ...o,
        })
      );

    const lineAt = lineIndex(content);
    // Props destructured in a component signature, read once per file.
    // Gate-3 G32: the first draft built and ran a whole-file RegExp per
    // useState(x) match to answer this. Both names of a rename (`{ a: b }`)
    // count, as the per-match pattern's \b did.
    const destructuredProps = new Set();
    for (const dm of code.matchAll(
      /function\s+[A-Z]\w*\s*\(\s*\{([^}]{0,400})\}|=\s*\(\s*\{([^}]{0,400})\}\s*\)\s*=>/g
    ))
      for (const part of (dm[1] ?? dm[2] ?? '').split(','))
        for (const n of part.split(/[:=]/))
          if (/^\s*\w+\s*$/.test(n)) destructuredProps.add(n.trim());

    // Duplicate fetch: the same literal URL fetched from 2+ sites in one
    // file — the tell of copy-pasted data loading with no shared layer.
    const urlSites = new Map();
    codeLines.forEach((line, i) => {
      const m = line.match(/fetch\s*\(\s*['"`]([^'"`\n]{4,120})['"`]/);
      if (!m) return;
      // Gate-1: two POSTs to one REST endpoint are two mutations, not
      // duplicated loading — only read-shaped fetches count.
      const opts = codeLines.slice(i, i + 3).join(' ');
      if (/method\s*:\s*['"](?:POST|PUT|PATCH|DELETE)/i.test(opts)) return;
      if (!urlSites.has(m[1])) urlSites.set(m[1], []);
      urlSites.get(m[1]).push(i + 1);
    });
    for (const [url, sites] of urlSites) {
      if (sites.length < 2) continue;
      push(sites[1], {
        id: `data-dup-fetch-${file.path}-${sites[1]}`,
        title: `The same URL is fetched from ${sites.length} places`,
        severity: 'low',
        remediation: `'${url.slice(0, 60)}' is requested at lines ${sites.join(', ')} of this file. Each site pays its own round trip and can disagree with the others mid-flight. Load it once in a shared hook or loader and pass the result down.`,
      });
    }

    codeLines.forEach((line, i) => {
      const ln = i + 1;
      // Polling with no backoff: a fetch inside setInterval hammers the
      // server at a fixed rate, including while it is failing.
      const pollWindow = codeLines.slice(i, i + 4).join(' ');
      // Gate-1: a heartbeat/beacon POST is not data polling — nothing is
      // read back and the fixed cadence IS the contract; backing off would
      // mark live sessions dead. Fire only when the response is consumed.
      const beaconShaped =
        /method\s*:\s*['"](?:POST|PUT)/.test(pollWindow) && !/\.then\s*\(|await\s/.test(pollWindow);
      if (
        // Bounded: `[^}]*` rescanned to the end of the window from every
        // setInterval on a brace-free minified line (Gate-3 G15).
        /setInterval\s*\(\s*(?:async\s*)?\([^)]{0,100}\)\s*=>\s*\{?[^}]{0,400}fetch\s*\(|setInterval\s*\(\s*(?:async\s+)?function[^{]{0,100}\{[^}]{0,400}fetch\s*\(/.test(
          pollWindow
        ) &&
        /setInterval/.test(line) &&
        !beaconShaped
      ) {
        push(ln, {
          id: `data-poll-nobackoff-${file.path}-${ln}`,
          title: 'Fixed-rate polling with no backoff',
          severity: 'medium',
          remediation:
            'When the server slows or errors, a fixed interval keeps hitting it at full rate — the exact moment it needs less traffic, it gets the same. Poll with setTimeout that reschedules itself and stretches the delay on failure, or use the platform: SSE or a WebSocket.',
        });
      }
      // Gate-2 (C24): the self-rescheduling setTimeout poll with a FIXED
      // literal delay is the same defect wearing this check's own
      // remediation — `setTimeout(poll, 5000)` at the end of a fetching
      // poll() never stretches on failure. A variable delay is the backoff
      // signal, so only a numeric-literal delay fires.
      const st = line.match(/setTimeout\s*\(\s*(\w+)\s*,\s*\d+\s*\)/);
      if (st) {
        const fnName = st[1];
        const bodyAbove = codeLines.slice(Math.max(0, i - 12), i).join('\n');
        const declaresSelf = new RegExp(
          `(?:function\\s+${fnName}\\s*\\(|(?:const|let|var)\\s+${fnName}\\s*=)`
        ).test(bodyAbove);
        const consumesFetch = /await\s+fetch\s*\(|fetch\s*\([^)]*\)\s*\.then\s*\(/.test(bodyAbove);
        if (declaresSelf && consumesFetch) {
          push(ln, {
            id: `data-poll-nobackoff-${file.path}-${ln}`,
            title: 'Fixed-rate polling with no backoff',
            severity: 'medium',
            remediation:
              'This poll reschedules itself at the same fixed delay whether the last request succeeded or failed, so a struggling server keeps getting full-rate traffic. Track failures and stretch the delay (delay = Math.min(delay * 2, max)), resetting it on success, or use SSE or a WebSocket.',
          });
        }
      }
      // TanStack Query object form without a queryKey.
      if (/useQuery\s*\(\s*\{/.test(line)) {
        const windowText = codeLines.slice(i, Math.min(codeLines.length, i + 6)).join(' ');
        if (/queryFn\s*:/.test(windowText) && !/queryKey\s*:/.test(windowText)) {
          push(ln, {
            id: `data-noquerykey-${file.path}-${ln}`,
            title: 'useQuery without a queryKey',
            severity: 'medium',
            remediation:
              'The key IS the cache identity: without one, results cannot be cached, deduplicated, or invalidated, and TanStack Query v5 rejects the call outright. Give the query a stable array key that includes its parameters: queryKey: ["user", id].',
          });
        }
      }
      // State seeded from a prop: mirrors the prop at mount and ignores
      // every later change to it.
      // Gate-2 (C25): nested paths count — useState(props.user.name) and
      // useState(user.name) with a destructured `user` mirror the prop just
      // as hard as the flat spelling did.
      const sp =
        line.match(/useState\s*\(\s*props\.((?:\w+\.)*\w+)\s*\)/) ||
        line.match(/useState\s*\(\s*(\w+(?:\.\w+)*)\s*\)/);
      if (sp) {
        const name = sp[1];
        const segs = name.split('.');
        const rootName = segs[0];
        const isProp = /props\./.test(sp[0]) || destructuredProps.has(rootName);
        // Gate-1: initial*/default* names ARE the fix this check teaches —
        // react.dev blesses them as the visible one-time-read signal.
        const signposted = segs.some((s) => /^(?:initial|default)/i.test(s));
        if (
          isProp &&
          !signposted &&
          !/use(?:Effect|Memo)/.test(codeLines.slice(Math.max(0, i - 2), i + 4).join(' '))
        ) {
          push(ln, {
            id: `data-state-from-prop-${file.path}-${ln}`,
            title: `useState seeded from prop ${name}`,
            severity: 'medium',
            remediation:
              'useState reads its argument once, at first render; when the parent later passes a new value, this copy silently keeps the old one. If the prop should drive the value, use the prop directly (derive, don’t store). If this is intentionally an initial value, name it initialX so the one-time read is visible.',
          });
        }
      }
    });

    // Fetch in render: a component body calls fetch outside any effect,
    // handler, or callback — a request per render.
    if (/\.(?:jsx|tsx)$/i.test(file.path)) {
      // Collect effect spans to exclude.
      const effectSpans = [];
      const eRe = /\buse(?:Layout)?Effect\s*\(/g;
      let em2;
      while ((em2 = eRe.exec(code)) !== null) {
        let depth = 0;
        for (
          let k = em2.index + em2[0].length - 1;
          k < Math.min(code.length, em2.index + 6000);
          k++
        ) {
          if (code[k] === '(') depth++;
          else if (code[k] === ')') {
            depth--;
            if (depth === 0) {
              effectSpans.push([em2.index, k]);
              break;
            }
          }
        }
      }
      // Gate-3 G16/G25: per fetch, a linear scan of every effect span and a
      // prefix re-split for the line number made this doubly quadratic, the
      // worst v2 hotspot (7.3s at 400KB). One byte map of effect-covered
      // offsets, one line index.
      const inEffect = new Uint8Array(code.length + 1);
      for (const [a, b] of effectSpans) inEffect.fill(1, a + 1, b);
      const fRe = /\bfetch\s*\(/g;
      let fm2;
      while ((fm2 = fRe.exec(code)) !== null) {
        const idx = fm2.index;
        if (inEffect[idx]) continue;
        const ln = lineAt(idx);
        const lineText = codeLines[ln - 1] || '';
        // Inside a handler attribute, a named handler, a loader, or any
        // function that is not the component itself: approximate by
        // requiring the line NOT to be inside on*= JSX, and the nearest
        // preceding function-ish opener to be a component (Capitalized).
        if (
          /\bon[A-Z]\w*\s*=|=>\s*fetch|function\s+\w|async\s+function|const\s+\w+\s*=\s*(?:async\s*)?\(/.test(
            lineText
          )
        )
          continue;
        const before = code.slice(Math.max(0, idx - 2000), idx);
        const opener = [
          ...before.matchAll(
            /function\s+([A-Za-z_]\w*)\s*\(|const\s+([A-Za-z_]\w*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{/g
          ),
        ].pop();
        const openerName = opener ? opener[1] || opener[2] : null;
        if (!openerName || !/^[A-Z]/.test(openerName)) continue;
        // Gate-1: an async component is a React Server Component — its body
        // runs once per request on the server with framework caching; the
        // remediation (move to useEffect) is forbidden there.
        if (
          opener &&
          /async/.test(code.slice(Math.max(0, opener.index - 40), opener.index + opener[0].length))
        )
          continue;
        if (/(^|\/)app\//.test(file.path) && !/['"]use client['"]/.test(content.slice(0, 400)))
          continue;
        push(ln, {
          id: `data-fetch-in-render-${file.path}-${ln}`,
          title: `fetch called during render of ${openerName}`,
          severity: 'medium',
          remediation:
            'The component body runs on every render, so every render fires the request, and setting state from its result causes the next one. Move the fetch into useEffect with the right dependencies, an event handler, or your framework’s loader.',
        });
      }
    }

    // Fetch flow with neither loading nor error state anywhere in the file:
    // the UI has two states it cannot represent.
    if (
      /\.(?:jsx|tsx)$/i.test(file.path) &&
      /await\s+fetch\s*\(|fetch\s*\([^)]*\)\s*\.then/.test(code) &&
      /useState/.test(code) &&
      !/\b(?:loading|isLoading|pending|isPending|fetching|isFetching)\b/i.test(code) &&
      !/\b(?:error|isError|failed|failure)\b/i.test(code)
    ) {
      const idx = code.search(/fetch\s*\(/);
      push(lineAt(idx), {
        id: `data-no-ui-states-${file.path}`,
        title: 'Fetch with no loading or error state',
        severity: 'low',
        remediation:
          'Between click and response the screen shows stale data as if it were current, and on failure it shows it forever. Track loading and error alongside the data — three states, three renders the user can trust.',
      });
    }
  });
  return findings;
}
