// src/lib/probes/v2/react.js
//
// F1: React and component hygiene (docs/preflight-v2-spec.md §F1, 22-probe
// roster). Hooks shipped in 2019; the AI tools learned the new syntax from a
// corpus where most code still used the old one, so effects leak listeners,
// dependency arrays lie, and components get defined inside components.
//
// Severity ceiling: MEDIUM — deliberately matching F7. The risk TIER takes
// the worst severity present, and a correctness finding must not brand a
// repo HIGH RISK (pinned by calibration-acceptance-v1). Whether health-axis
// findings should ever reach high is the parked class-ceiling decision;
// until it is made, these families teach at medium and below. The family
// scores on the health axis, not the headline security number.
//
// Roster entries deliberately not built, with reasons:
//   #7  race_condition_in_effect — merged into #4: the fetch-without-abort
//       check IS the stalest observable slice of the race; a standalone
//       flow-sensitive race detector needs dataflow the engine does not have.
//   #10 effect_should_be_event_handler — requires inferring what the author
//       meant the effect to react to; adversarial modeling put every
//       realistic fixture on both sides of the line. Declined as
//       FP-dominated (spec confidence: medium).
//   #20 dangerouslysethtml_unguarded — already owned by the Code Injection
//       probe ('dangerouslySetInnerHTML receives a non-constant value');
//       a second card for the same attribute is a duplicate, not coverage.
//
// Effect analysis is TEXTUAL: `useEffect(` spans are extracted by balanced-
// paren walking with a hard character budget, so the checks work identically
// on .ts/.tsx (which acorn cannot parse) and survive unparseable source. AST
// checks (conditional hooks, setter-in-render, nested components) run only
// on /\.(?:jsx?|mjs|cjs)$/i per the F7 precedent.

import { isTestFile, isScannerSelfSource } from '../../file-filter.js';
import { maskCommentsForPath, maskCodeShapeForPath } from '../_internal/masking.js';
import { parseModule, walk } from './context.js';
import { lineIndex } from './line-index.js';

// Named thresholds (tests and the Learn page read these).
export const REACT_EFFECT_SPAN_BUDGET = 6000;
export const REACT_HOOK_FILE_RE = /\.(?:[jt]sx?|mjs|cjs)$/i;
export const REACT_AST_FILE_RE = /\.(?:jsx?|mjs|cjs)$/i;

const finding = (o) => ({
  probe: 'React Hygiene',
  category: 'Code Correctness',
  severity: 'medium',
  cwe: 'CWE-1164',
  ...o,
});

// Balanced-paren span starting at the index of the opening paren. Returns
// the argument text (without the outer parens) or null when unbalanced
// within budget — half-typed source simply yields no span, never a crash.
function readCallSpan(content, openParen, budget = REACT_EFFECT_SPAN_BUDGET) {
  let depth = 0;
  const end = Math.min(content.length, openParen + budget);
  for (let i = openParen; i < end; i++) {
    const ch = content[i];
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) return content.slice(openParen + 1, i);
    }
  }
  return null;
}

// Identifiers go into dynamic patterns escaped: `$t` as a timer id turned
// `\b$t\s*=` into an end anchor mid-pattern and the leak check stood down
// on exactly the effect it existed for (Gate-3 G13).
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Index of the closing brace of the effect callback's block body, or -1 for
// a concise body. The span scanners below all key off this one scan.
function callbackClose(span) {
  const open = span.search(/=>\s*\{|function[^{]*\{/);
  if (open === -1) return -1;
  let depth = 0;
  for (let i = span.indexOf('{', open); i < span.length; i++) {
    if (span[i] === '{') depth++;
    else if (span[i] === '}' && --depth === 0) return i;
  }
  return -1;
}

// The cleanup function of an effect callback: everything from the effect's
// OWN `return () =>` or `return function` to the end of the span. '' when
// the effect returns nothing (or returns a value, which is its own defect
// but not this one's). Gate-3 G36: the first draft matched `return () =>`
// anywhere, so a nested helper's returned closure was read as the cleanup
// and a listener added after it was exempted as "cleanup text". A return
// inside the effect's own if-block still counts (`if (pending) { const t =
// setTimeout(...); return () => clearTimeout(t); }` is correct code and
// drew a timer finding when only depth-1 returns were read); a return
// inside a nested function or arrow body does not.
function cleanupOf(span) {
  const open = span.search(/=>\s*\{|function[^{]*\{/);
  if (open === -1) return '';
  const start = span.indexOf('{', open);
  const fnBrace = []; // per open brace: does it open a nested function body?
  for (let i = start; i < span.length; i++) {
    const ch = span[i];
    if (ch === '{') {
      const before = span.slice(Math.max(start, i - 80), i).trimEnd();
      fnBrace.push(i !== start && (/=>$/.test(before) || /\bfunction\b[^{]*\)$/.test(before)));
    } else if (ch === '}') {
      fnBrace.pop();
      if (fnBrace.length === 0) break;
    } else if (
      ch === 'r' &&
      !fnBrace.includes(true) &&
      /^return\s+(?:async\s+)?(?:\(\s*\)\s*=>|function\b)/.test(span.slice(i, i + 40))
    )
      return span.slice(i);
  }
  return '';
}

// Gate-1 (2026-09-03): the resource checks may only accuse an effect whose
// cleanup they can actually READ — `return unsubscribe;`, `return cleanup;`
// and the Redux concise-arrow implicit return are real cleanups.
// Gate-2 rebuilt this precisely: the first draft matched `return` ANYWHERE
// in the span, so a nested helper's `return fetchStatus();` exempted an
// effect with no cleanup at all, `return timerId;` (which React rejects at
// runtime) vouched for two leaks, and EVERY concise arrow was deferred —
// including `() => window.addEventListener(...)`, which returns undefined.
// Now: only a TOP-LEVEL return of the callback body counts, an identifier
// return must not trace to a timer id, and a concise body defers only when
// its expression is a subscription-style call that returns a disposer.
function cleanupIsOpaque(span) {
  // Concise body: opaque only when the single expression is a call whose
  // API returns an unsubscribe/disposer (store.subscribe, emitter.on,
  // onSnapshot, watch). addEventListener/setInterval return nothing.
  if (/^\s*(?:async\s*)?\(\s*\)\s*=>\s*[^\s{]/.test(span)) {
    return /\.\s*(?:subscribe|on|once|listen|watch|addListener|observe)\s*\(|\bonSnapshot\s*\(/.test(
      span
    );
  }
  // Block body: scan for a return at brace-depth 1 of the callback.
  const open = span.search(/=>\s*\{|function[^{]*\{/);
  if (open === -1) return false;
  let i = span.indexOf('{', open);
  let depth = 0;
  for (; i < span.length; i++) {
    const ch = span[i];
    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) break;
    } else if (depth === 1 && span.startsWith('return', i) && /\W/.test(span[i + 6] || ' ')) {
      const rest = span.slice(i + 6);
      const idm = rest.match(/^\s+([A-Za-z_$][\w$]*)\s*[(;\n]/);
      if (!idm) continue; // `return () =>` etc. — cleanupOf reads those
      // An identifier assigned from a timer in this same span is an id,
      // not a cleanup — React itself warns on it.
      // (?<![\w$]) rather than \b: a $-initial identifier has no word
      // boundary before it, so \b never matched `$t` (Gate-3 G13).
      if (new RegExp(`(?<![\\w$])${esc(idm[1])}\\s*=\\s*set(?:Timeout|Interval)\\s*\\(`).test(span))
        return false;
      return true;
    }
  }
  return false;
}

// The dependency segment: the text after the callback's closing brace and
// a comma. null when the effect has no second argument at all. Gate-3 G5:
// matching the FIRST `},` in the span let `const opts = { a: 1 }, extra = 2`
// inside the body stand in for a deps array that was not there.
function depsOf(span) {
  const close = callbackClose(span);
  if (close !== -1) {
    const m = span.slice(close + 1).match(/^\s*,([\s\S]*)$/);
    return m ? m[1].trim() : null;
  }
  // Concise-arrow effect body: `useEffect(() => setMounted(true), [])` has
  // no closing brace; the deps are the trailing array after the last comma.
  const c = span.match(/,\s*(\[[\s\S]*\])\s*$/);
  return c ? c[1].trim() : null;
}

export function probeReactHygiene(files) {
  const findings = [];
  // Gate-1: a Vue composable drew the rules-of-hooks lesson. Vue composables
  // have no call-order constraint (state is per-call, not slot-indexed), so
  // when the project declares vue/svelte/angular and no react, this family
  // has nothing true to say and stands down entirely.
  const pkgs = files.filter(
    (f) => /(^|\/)package\.json$/.test(f.path) && !/node_modules/.test(f.path)
  );
  const declaresReact = pkgs.some((f) => /"react(?:-dom)?"\s*:/.test(f.content || ''));
  const declaresOtherFw = pkgs.some((f) =>
    /"(?:vue|svelte|@angular\/core)"\s*:/.test(f.content || '')
  );
  if (declaresOtherFw && !declaresReact) return findings;
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!REACT_HOOK_FILE_RE.test(file.path)) return;
    const content = file.content || '';
    if (!content.trim()) return;
    // Cheap file gate: none of the family's vocabulary, no work. Must cover
    // every check's trigger, not just hooks — the first draft gated on hooks
    // alone and silently skipped the prop/Provider/App-Router checks in
    // files that used none.
    if (
      !/use(?:Effect|LayoutEffect|State|Ref|Memo|Callback)|forwardRef|React\.lazy|\blazy\s*\(|\.Provider|\.map\s*\(|(?:component|render|element)=\{|\.current\s*\}|window\.|document\.|localStorage|\bfunction\s+[A-Z]|\b(?:const|let|var)\s+[A-Z]\w*\s*=/.test(
        content
      )
    )
      return;
    const code = maskCommentsForPath(file.path, content);
    // String-blind view for the span scanners: a `)` or `}` inside a log
    // string truncated an effect span before its cleanup and a correct
    // effect was accused (Gate-3 G3, G4). Both masks preserve length, so an
    // offset found on one view reads the same source on the other.
    const shape = maskCodeShapeForPath(file.path, content);
    const lineAt = lineIndex(content);
    // Gate-3 G27: the stale-closure check re-ran this matchAll over the whole
    // file for every []-deps effect. Once per file.
    const stateNames = [
      ...content.matchAll(/const\s*\[\s*(\w+)\s*,\s*set[A-Z]\w*\s*\]\s*=\s*useState/g),
    ].map((x) => x[1]);

    // ---- Effect-span checks (1,2,3,4,5,6,8,9,11) ----
    const effectRe = /\buse(?:Layout)?Effect\s*(\()/g;
    let em;
    while ((em = effectRe.exec(code)) !== null) {
      const openParen = em.index + em[0].length - 1;
      const spanShape = readCallSpan(shape, openParen);
      if (spanShape === null) continue;
      const ln = lineAt(em.index);
      const cleanup = cleanupOf(spanShape);
      const body = cleanup ? spanShape.slice(0, spanShape.length - cleanup.length) : spanShape;
      const opaqueCleanup = cleanup === '' && cleanupIsOpaque(spanShape);
      // An arrow cleanup that CALLS a helper (`return () => teardown(ref);`)
      // delegates the release — the specific verb lives in the helper, so
      // the per-resource verb tests below cannot see it (Gate-1 C3).
      const cleanupDelegates =
        cleanup !== '' &&
        /=>\s*\{?\s*[A-Za-z_$][\w$.]*\s*\(|function\b[^{]*\{\s*[A-Za-z_$][\w$.]*\s*\(/.test(
          cleanup
        ) &&
        !/removeEventListener|clearInterval|clearTimeout|unsubscribe|\.close\s*\(|disconnect|unobserve|\.abort\s*\(/.test(
          cleanup
        );
      // Cancellation vocabulary is matched on the string-blanked span with
      // word boundaries — Gate-2: 'status=active' in a URL and a
      // 'lastActive' data field both vouched for uncancellable fetches.
      const push = (o) => findings.push(finding({ file: file.path, line: ln, ...o }));
      const evidence = code
        .slice(em.index, em.index + 160)
        .split('\n')[0]
        .trim()
        .slice(0, 160);

      // 1. addEventListener without removeEventListener in cleanup. The
      //    AbortSignal form (`{ signal }` + abort in cleanup) and `once:
      //    true` listeners release themselves.
      if (
        !opaqueCleanup &&
        !cleanupDelegates &&
        /\baddEventListener\s*\(/.test(body) &&
        !/removeEventListener\s*\(/.test(cleanup) &&
        !(/\bsignal\b/.test(body) && /\.abort\s*\(/.test(cleanup)) &&
        !/once\s*:\s*true/.test(body)
      ) {
        push({
          id: `react-effect-listener-${file.path}-${ln}`,
          title: 'Effect adds a listener it never removes',
          severity: 'medium',
          evidence,
          remediation:
            'Every mount hangs a new listener and every unmount leaves it behind; hot-reload a dozen times and a dozen handlers fire per event. Name the handler, addEventListener in the effect, and return () => removeEventListener with the same reference.',
        });
      }
      // 2. setInterval (always) / assigned setTimeout without a clear in
      //    cleanup.
      if (
        !opaqueCleanup &&
        !cleanupDelegates &&
        ((/\bsetInterval\s*\(/.test(body) && !/clearInterval\s*\(/.test(cleanup)) ||
          (/\b(?:const|let|var)\s+[\w$]+\s*=\s*setTimeout\s*\(|[\w$]+\.current\s*=\s*setTimeout\s*\(/.test(
            body
          ) &&
            !/clearTimeout\s*\(/.test(cleanup)))
      ) {
        push({
          id: `react-effect-timer-${file.path}-${ln}`,
          title: 'Effect starts a timer it never clears',
          severity: 'medium',
          evidence,
          remediation:
            'An interval keeps firing after the component is gone, updating state that no longer exists. Keep the id and return () => clearInterval(id) (or clearTimeout) from the effect.',
        });
      }
      // 3. .subscribe( without unsubscribe/remove in cleanup.
      if (
        !opaqueCleanup &&
        !cleanupDelegates &&
        /\.\s*subscribe\s*\(/.test(body) &&
        !/(?:unsubscribe|\.remove\s*\(|\.off\s*\()/.test(cleanup)
      ) {
        push({
          id: `react-effect-subscription-${file.path}-${ln}`,
          title: 'Effect subscribes and never unsubscribes',
          severity: 'medium',
          evidence,
          remediation:
            'The subscription outlives the component and keeps pushing into dead state. Keep the handle (const sub = x.subscribe(...)) and return () => sub.unsubscribe().',
        });
      }
      // 5. new WebSocket without close in cleanup.
      if (
        !opaqueCleanup &&
        !cleanupDelegates &&
        /\bnew\s+WebSocket\s*\(/.test(body) &&
        !/\.close\s*\(/.test(cleanup)
      ) {
        push({
          id: `react-effect-websocket-${file.path}-${ln}`,
          title: 'Effect opens a WebSocket it never closes',
          severity: 'medium',
          evidence,
          remediation:
            'Every remount opens another socket; the server sees a pile of zombie connections from one tab. Keep the socket and return () => ws.close() from the effect.',
        });
      }
      // 6. Observer without disconnect/unobserve in cleanup.
      if (
        !opaqueCleanup &&
        !cleanupDelegates &&
        /\bnew\s+(?:Mutation|Intersection|Resize|Performance)Observer\s*\(/.test(body) &&
        !/(?:disconnect|unobserve)\s*\(/.test(cleanup)
      ) {
        push({
          id: `react-effect-observer-${file.path}-${ln}`,
          title: 'Effect creates an observer it never disconnects',
          severity: 'medium',
          evidence,
          remediation:
            'Observers hold references to the nodes they watch, so neither the observer nor the DOM it watched can be collected. Return () => observer.disconnect() from the effect.',
        });
      }
      // 4 (+7 merged). fetch in an effect with no AbortController wiring and
      //    no cancelled-flag: the response lands after unmount and the race
      //    writes stale state.
      if (
        /\bfetch\s*\(|\baxios\b/.test(body) &&
        /\bawait\b|\.then\s*\(/.test(body) &&
        !/AbortController|\bsignal\b/i.test(spanShape) &&
        // Gate-1: stems, case-insensitive — didCancel (the most-taught
        // spelling of the flag), axios CancelToken / source.cancel(),
        // alive/disposed/unmounted variants.
        // Gate-2: word-bounded on the blanked span — 'lastActive' and URL
        // query text are not flags; camel prefixes (didCancel, wasAborted)
        // are spelled out because \b cannot see an intra-word boundary.
        !/\b(?:(?:did|is|was|should|un)?_?(?:cancel|abort)\w*|ignored?|(?:is|un|did)?_?mounted|stale|alive|disposed)\b/i.test(
          spanShape
        )
      ) {
        push({
          id: `react-effect-abort-${file.path}-${ln}`,
          title: 'Effect fetches without cancellation',
          severity: 'medium',
          evidence,
          remediation:
            'Navigate away mid-request and the response still lands, writing state into an unmounted component, and two quick re-renders can resolve out of order. Create an AbortController in the effect, pass its signal to fetch, and return () => controller.abort().',
        });
      }
      // 9. No dependency array at all: the effect runs after every render.
      const deps = depsOf(spanShape);
      if (deps === null && /set[A-Z]\w*\s*\(|fetch\s*\(/.test(body)) {
        push({
          id: `react-effect-nodeps-${file.path}-${ln}`,
          title: 'Effect has no dependency array',
          severity: 'medium',
          evidence,
          remediation:
            'Without a dependency array the effect runs after every render. If it also sets state or fetches, that is a render loop or a request storm. Add the array: [] for once-on-mount, or list what the effect actually reads.',
        });
      }
      // 11. Object/array/function literal inline in the deps array: a fresh
      //     identity every render, so the effect re-runs every render.
      // `[steps[0]]` is member access with stable identity, not a literal —
      // only object/arrow/function literals defeat the comparison (Gate-1).
      if (deps !== null && /^\[[^\]]*(?:\{|\(\s*[\w,\s]*\)\s*=>|\bfunction\b)/.test(deps)) {
        push({
          id: `react-effect-literaldeps-${file.path}-${ln}`,
          title: 'Dependency array holds a fresh literal every render',
          severity: 'medium',
          evidence,
          remediation:
            'An object, array, or arrow literal in the deps array has a new identity on every render, so the comparison always fails and the effect always re-runs. Hoist the value, memoize it with useMemo/useCallback, or list its primitive fields instead.',
        });
      }
      // 8. Stale closure: [] deps but the effect body reads a useState value
      //    inside an interval or listener callback.
      if (deps !== null && /^\[\s*\]$/.test(deps)) {
        const inCallback = /(?:setInterval|addEventListener)\s*\(/.test(body);
        // Bare identifier reads only: `.error`, `'error'` and "error" are
        // event properties and string literals, not state reads (Gate-1: an
        // error-event listener fired on the state named error).
        const reads = stateNames.find((n) => new RegExp(`(?<![.'"\\w])${n}\\b`).test(body));
        if (inCallback && reads) {
          push({
            id: `react-effect-staleclosure-${file.path}-${ln}`,
            title: `Effect callback closes over stale state (${reads})`,
            severity: 'medium',
            evidence,
            remediation:
              'The callback captured the state value from the render when the effect ran, and with [] deps that render is the first one, forever. Use the functional updater (setX(x => ...)), a ref, or list the value in the deps array.',
          });
        }
      }
    }

    // ---- Line-shaped checks (14, 16, 17, 18, 19, 21, 22) ----
    const codeLines = code.split('\n');
    const rawLines = content.split('\n');
    const pushLine = (i, o) =>
      findings.push(
        finding({
          file: file.path,
          line: i + 1,
          evidence: (rawLines[i] ?? '').trim().slice(0, 160),
          ...o,
        })
      );

    codeLines.forEach((line, i) => {
      // 19. key={i} where i is the map callback's index parameter. Read
      // across the next two lines, since Prettier puts the element on its
      // own line (Gate-3 G6), and bounded at 200 characters between the
      // arrow and the key: the open-ended lazy scan was quadratic on a
      // minified line of .map calls (G33). The match has to start on this
      // line so a window never reports the same map twice.
      const km = codeLines
        .slice(i, i + 3)
        .join(' ')
        .match(/\.map\s*\(\s*\(\s*\w+\s*,\s*(\w+)\s*\)\s*=>[^]{0,200}?\bkey=\{\s*(\w+)\s*\}/);
      if (km && km[1] === km[2] && km.index < line.length) {
        pushLine(i, {
          id: `react-keyindex-${file.path}-${i}`,
          title: 'Array index used as the key in a dynamic list',
          severity: 'medium',
          remediation:
            'When the list reorders or an item is removed, index keys make React reuse the wrong DOM and state: inputs keep the neighbor’s text, checkboxes stay checked on the wrong row. Key by a stable id from the data.',
        });
      }
      // 16. Inline anonymous component in a component-typed JSX prop.
      // `render`/`element` render-props are INVOKED, not mounted — nothing
      // remounts (Gate-1: fired on react-hook-form's Controller render and
      // React Router v5's recommended render=). Only component= treats the
      // value as a component type.
      // Gate-3 G14: `\s*` beside a class that also ate whitespace backtracked
      // quadratically on a long run of spaces; the parameter list is one
      // bounded class now.
      if (/\bcomponent=\{\s*(?:\([\w{},\s]{0,200}\)\s*=>|function\b)/.test(line)) {
        pushLine(i, {
          id: `react-inlinecomponent-${file.path}-${i}`,
          title: 'Anonymous component defined inline in a prop',
          severity: 'medium',
          remediation:
            'The prop gets a brand-new component type every render, so React unmounts and remounts the whole subtree each time, losing its state. Define the component once at module scope and pass the reference.',
        });
      }
      // 18. Context Provider fed an inline object/array literal.
      if (/\.Provider\s+value=\{\s*[\[{]/.test(line)) {
        pushLine(i, {
          id: `react-contextvalue-${file.path}-${i}`,
          title: 'Context value is a fresh literal every render',
          severity: 'medium',
          remediation:
            'Every render creates a new object identity, so every consumer of the context re-renders whether its data changed or not. Wrap the value in useMemo keyed on what it actually contains.',
        });
      }
      // 14. ref.current rendered as content.
      if (/\{\s*\w+\.current\s*\}\s*</.test(line) && /useRef\s*\(/.test(code)) {
        pushLine(i, {
          id: `react-refasstate-${file.path}-${i}`,
          title: 'ref.current rendered as content',
          severity: 'low',
          remediation:
            'Changing a ref does not re-render, so the screen shows whatever the ref held at the last render caused by something else. If the value should appear in the UI, it is state: useState, not useRef.',
        });
      }
    });

    // 17. forwardRef without displayName: components show as Anonymous in
    //     DevTools and error stacks.
    if (/\bforwardRef\s*\(/.test(code) && !/\.displayName\s*=/.test(code)) {
      const idx = code.search(/\bforwardRef\s*\(/);
      findings.push(
        finding({
          id: `react-forwardref-name-${file.path}`,
          title: 'forwardRef component has no displayName',
          severity: 'info',
          file: file.path,
          line: lineAt(idx),
          evidence: (rawLines[lineAt(idx) - 1] ?? '').trim().slice(0, 160),
          remediation:
            'Wrapped components render as Anonymous in DevTools and error stacks. Set MyComponent.displayName = "MyComponent" after the forwardRef call.',
        })
      );
    }
    // 21. React.lazy without Suspense anywhere in the file set is checked
    //     per-file: lazy( present, Suspense absent in this file.
    if (
      /\b(?:React\.)?lazy\s*\(\s*\(\s*\)\s*=>\s*import\s*\(/.test(code) &&
      !/Suspense/.test(code)
    ) {
      const idx = code.search(/\b(?:React\.)?lazy\s*\(/);
      findings.push(
        finding({
          id: `react-lazy-nosuspense-${file.path}`,
          title: 'React.lazy without a Suspense boundary in the file',
          severity: 'medium',
          file: file.path,
          line: lineAt(idx),
          evidence: (rawLines[lineAt(idx) - 1] ?? '').trim().slice(0, 160),
          remediation:
            'A lazy component rendered outside any <Suspense> boundary throws while its chunk loads. Wrap the render site in <Suspense fallback={...}>. If the boundary lives in another file, add a comment naming it where the lazy component is used.',
        })
      );
    }
    // 22. Next.js App Router server component using client-only APIs.
    // Route-entry files only (page/layout/template): 'use client' marks the
    // client BOUNDARY, not every file — a colocated hook imported by a
    // client component runs as client code with no directive of its own
    // (Gate-1: fired on standard App Router colocation).
    if (
      // Gate-3 G2: a dead `(?:^|/)` alternative mid-pattern required a slash
      // between app/ and the filename, which excluded the root app/page.tsx.
      /(^|\/)app\/(?:.*\/)?(?:page|layout|template)\.(?:jsx|tsx|js|ts)$/i.test(file.path) &&
      !/['"]use client['"]/.test(content.slice(0, 400)) &&
      files.some((f) => /(^|\/)next\.config\.[cm]?js$/.test(f.path)) &&
      /\buse(?:State|Effect|LayoutEffect|Reducer)\s*\(|\bwindow\.|\blocalStorage\b|\bdocument\./.test(
        code
      )
    ) {
      const idx = code.search(
        /\buse(?:State|Effect|LayoutEffect|Reducer)\s*\(|\bwindow\.|\blocalStorage\b|\bdocument\./
      );
      findings.push(
        finding({
          id: `react-server-clientapi-${file.path}`,
          title: 'Server component uses client-only APIs',
          severity: 'medium',
          file: file.path,
          line: lineAt(idx),
          evidence: (rawLines[lineAt(idx) - 1] ?? '').trim().slice(0, 160),
          remediation:
            'Files under app/ are server components unless they start with "use client". Hooks and browser globals do not exist there; the build fails or the page crashes at request time. Add "use client" at the top, or move the interactive part into its own client component.',
        })
      );
    }

    // ---- AST checks (12, 13, 15): parseable JS/JSX only ----
    if (!REACT_AST_FILE_RE.test(file.path)) return;
    const ast = parseModule(content);
    if (!ast) return;
    // walk() passes parents to the callback but does not attach them; the
    // checks below climb ancestor chains, so attach first (walk's descent
    // deliberately skips the 'parent' key).
    walk(ast, (node, parent) => {
      node.parent = parent;
    });
    const FN_TYPES = new Set([
      'FunctionDeclaration',
      'FunctionExpression',
      'ArrowFunctionExpression',
    ]);
    const isComponentName = (n) => typeof n === 'string' && /^[A-Z]/.test(n);
    const nameOf = (node, parent) =>
      node.id?.name ||
      (parent?.type === 'VariableDeclarator' ? parent.id?.name : undefined) ||
      undefined;
    // Setter names from useState destructuring.
    const setterNames = new Set(
      [...content.matchAll(/const\s*\[\s*\w+\s*,\s*(set[A-Z]\w*)\s*\]\s*=\s*useState/g)].map(
        (x) => x[1]
      )
    );
    walk(ast, (node, parent) => {
      // 15. Component defined inside a component.
      if (FN_TYPES.has(node.type)) {
        const outer = nameOf(node, parent);
        if (isComponentName(outer)) {
          walk(node.body, (inner, innerParent) => {
            if (!FN_TYPES.has(inner.type) || inner === node) return;
            const innerName = nameOf(inner, innerParent);
            if (isComponentName(innerName)) {
              findings.push(
                finding({
                  id: `react-nested-component-${file.path}-${inner.start}`,
                  title: `Component ${innerName} defined inside ${outer}`,
                  severity: 'medium',
                  file: file.path,
                  line: lineAt(inner.start),
                  evidence: content
                    .slice(inner.start, inner.start + 120)
                    .split('\n')[0]
                    .trim(),
                  remediation:
                    'Every render of the outer component creates a NEW inner component type, so React unmounts and remounts its whole subtree each render, discarding state and DOM. Move the inner component to module scope and pass data as props.',
                })
              );
            }
          });
        }
      }
      // 12. Hook called inside a conditional or loop.
      if (
        node.type === 'CallExpression' &&
        node.callee?.type === 'Identifier' &&
        /^use[A-Z]/.test(node.callee.name)
      ) {
        let p = parent;
        let depth = 0;
        while (p && depth < 40) {
          if (FN_TYPES.has(p.type)) break;
          if (
            p.type === 'IfStatement' ||
            p.type === 'ForStatement' ||
            p.type === 'ForOfStatement' ||
            p.type === 'WhileStatement' ||
            p.type === 'ConditionalExpression' ||
            (p.type === 'LogicalExpression' && p.right && node.start >= p.right.start)
          ) {
            findings.push(
              finding({
                id: `react-conditional-hook-${file.path}-${node.start}`,
                title: `${node.callee.name} called conditionally`,
                severity: 'medium',
                file: file.path,
                line: lineAt(node.start),
                evidence: content
                  .slice(node.start, node.start + 120)
                  .split('\n')[0]
                  .trim(),
                remediation:
                  'Hooks must run in the same order every render; a hook inside if/for/&& shifts the order the moment the condition flips, and React wires every later hook to the wrong state. Call the hook unconditionally and branch inside it or around its result.',
              })
            );
            break;
          }
          p = p.parent;
        }
      }
      // 13. State setter called directly in the render body.
      if (
        node.type === 'CallExpression' &&
        node.callee?.type === 'Identifier' &&
        setterNames.has(node.callee.name)
      ) {
        // Walk up: the call must sit in a component function body with NO
        // intervening function (handler/effect callback) and not inside a
        // JSX attribute value.
        let p = parent;
        let crossedFn = 0;
        let componentFn = null;
        let inJsxAttr = false;
        let guarded = false;
        let hops = 0;
        while (p && hops < 60) {
          if (p.type === 'JSXAttribute') inJsxAttr = true;
          // A setter inside an if-guard is the OFFICIALLY documented
          // adjust-state-during-render pattern (react.dev, You Might Not
          // Need an Effect): the guard terminates after one re-render.
          // Gate-1: following the React docs drew this finding twice.
          if (p.type === 'IfStatement' || p.type === 'ConditionalExpression') guarded = true;
          if (FN_TYPES.has(p.type)) {
            const nm = nameOf(p, p.parent);
            if (isComponentName(nm)) {
              componentFn = nm;
              break;
            }
            crossedFn++;
          }
          p = p.parent;
          hops++;
        }
        if (componentFn && crossedFn === 0 && !inJsxAttr && !guarded) {
          findings.push(
            finding({
              id: `react-setter-in-render-${file.path}-${node.start}`,
              title: `${node.callee.name} called during render of ${componentFn}`,
              severity: 'medium',
              file: file.path,
              line: lineAt(node.start),
              evidence: content
                .slice(node.start, node.start + 120)
                .split('\n')[0]
                .trim(),
              remediation:
                'Setting state during render schedules another render, which sets state again: an infinite loop React stops with an error, after burning the frame budget. Move the call into an event handler or an effect with the right dependencies.',
            })
          );
        }
      }
    });
  });
  return findings;
}
