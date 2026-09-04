# Gate 3 confirmed defects (v2 families)

Three contextless attackers (crash safety, ReDoS/performance, logic correctness) against
the eleven v2 families at commit e48e58d. Every entry below was reproduced by the attacker
through the real PROBES registry and then independently re-reproduced by a second checker
whose default verdict was REFUTED. Refuted claims are not listed.

Generated 2026-09-04 from the run outputs. Nothing here is fixed yet.

## Contract violations (probe throws) (13)

### G12 `build-config.js`

**Defect.** probeBuildConfig throws a TypeError whenever the root package.json arrives with undefined, null, or missing content, because line 91 calls pkgFile.content.split('\n') with no guard (the JSON.parse on line 87 is inside try/catch but the split is not).

**Reproducer.** [{path:'package.json', content: undefined}, {path:'src/a.js', content:'fetch("/x")'}] — also reproduced with content: null and with the content key absent entirely

**Observed.** TypeError: Cannot read properties of undefined (reading 'split') — uncaught, escapes the probe; reproduced in 4 of the crash-battery fixture sets (content undefined, content null, content missing key, pkg undefined content + lockless)

### G13 `react.js`

**Defect.** The dynamic RegExp at line 114 is built from an identifier captured by [A-Za-z\_$][\w$]\* (line 110), so an identifier containing $ injects a regex end-of-input anchor and the pattern can never match; returning a $-named timer id from an effect is then wrongly accepted as an opaque cleanup and the timer-leak finding is silently suppressed.

**Reproducer.** useEffect(() => { const $t = setTimeout(tick, 100); return $t; }, []) in src/t.jsx — versus the byte-identical effect with the identifier renamed to t

**Observed.** With id 't': findings = ['react-effect-timer-src/t.jsx-3']. With id '$t': findings = [] — new RegExp('\\b$t\\s*=\\s*set(?:Timeout|Interval)\\s\*\\(') treats $ as an anchor mid-pattern and never matches, so cleanupIsOpaque returns true and check 2 stands down.

### G14 `react.js`

**Defect.** The check-16 regex at line 394 (/\bcomponent=\{\s*(?:\(\s*[\w{},\s]_\)\s_=>|function\b)/) has ambiguous overlapping quantifiers (\s* and [\w{},\s]* both eat whitespace) and backtracks quadratically on a long whitespace run after 'component={('.

**Reproducer.** One .jsx line: 'const A = () => <Route component={(' + ' '.repeat(N) + 'x} />' for N = 15000 / 30000 / 60000

**Observed.** Probe runtime 86ms / 306ms / 1225ms — 4x per size doubling (quadratic); a 60KB file already takes 1.2s. Standalone regex on 30K spaces: 313ms, confirming the attribution.

### G15 `data-state.js`

**Defect.** The polling regex at line 97 (setInterval...\([^)]_\)\s_=>\s*\{?[^}]*fetch\s\*\() rescans to end-of-window from every setInterval occurrence when the line contains no closing brace, going quadratic on one-line minified input.

**Reproducer.** Single-line .js file of 'setInterval((x)=>g(),1);' repeated to 100KB / 200KB / 400KB

**Observed.** Probe runtime 103ms / 415ms / 1620ms (quadratic); standalone regex on the 400KB window: 1657ms.

### G16 `data-state.js`

**Defect.** The fetch-in-render pass is doubly quadratic: per fetch site it recomputes the line number via code.slice(0, idx).split('\n') (line 211) and linearly scans the whole effectSpans array (line 210), so files with many effects and many fetches cost O(fetches x file size + fetches x effects).

**Reproducer.** .tsx file of 'useEffect(f);\nfetch(x);\n' repeated to 400KB (multi-line), and 'useEffect(f);fetch(x);' repeated to 100/200/400KB on one line

**Observed.** Multi-line 400KB: 7765ms. One-line: 407ms / 1421ms / 5155ms (quadratic scaling).

### G17 `async.js`

**Defect.** Check 6's per-line regex /\bawait\b[^;]_\.then\s_\(/ (line 190) rescans to end-of-line from every 'await' occurrence when the line has no semicolons, going quadratic on one-line input.

**Reproducer.** Single-line .js file of 'await a[0] ' repeated to 100KB / 200KB / 400KB

**Observed.** Probe runtime 245ms / 895ms / 3648ms (quadratic); standalone regex on the 400KB line: 3717ms.

### G18 `hallucinations.js`

**Defect.** The react-import regex at line 190 (import\s*\{([^}]+)\}\s*from\s\*['"]react['"], twinned at line 214 for next/navigation) scans [^}]+ to end-of-line from every 'import {' occurrence when no closing brace exists, going quadratic on one-line input.

**Reproducer.** Single-line .js file of "import {a from 'x' " repeated to 100KB / 200KB / 300KB, ending with " from 'react' " so the file gate passes

**Observed.** Probe runtime 317ms / 1202ms / 3048ms (quadratic); standalone regex on a 300KB line: 1326ms.

### G19 `db-patterns.js`

**Defect.** Line 115 recomputes const usesKnex = /knex.../.test(code) — a regex over the ENTIRE file content — inside codeLines.forEach for every single line, making the probe O(lines x bytes); near-miss 'knex' substrings defeat the engine's literal prescan and realize the full cost.

**Reproducer.** 400KB .js of short lines 'x.update(knexq);' (23,531 lines), scaled 100KB / 200KB / 400KB; also 'row.update(v); knexq...' long-line variant at 400KB

**Observed.** Dense-line scaling: 366ms / 1420ms / 5682ms (quadratic). Long-line 400KB variant: 740ms. The hoisted-once equivalent would be a single 400KB scan.

### G20 `perf.js`

**Defect.** The moment-import regex at line 105 contains an unbounded greedy '._' (import\s+[\w{_]\S*\s.*from\s+['"]moment...) that scans and backtracks to end-of-line from every 'import' occurrence, going quadratic on one-line input with many imports and no moment.

**Reproducer.** Single-line .js file of "import x from 'y';" repeated to 100KB / 200KB / 400KB

**Observed.** Probe runtime 386ms / 1450ms / 5705ms (quadratic); standalone regex on the 400KB line: 5838ms.

### G21 `a11y-semantics.js`

**Defect.** Line 71 runs /:focus-visible/.test(code) — a scan of the whole file — once per outline:none-matching line instead of once per file, making the outline check O(matching-lines x bytes).

**Reproducer.** 400KB .css of '.a { outline: none; }' per line (18,183 lines), no :focus-visible anywhere; scaled 100KB / 200KB / 400KB

**Observed.** 95ms / 365ms / 1431ms (quadratic). Attribution proof: adding one stylesheet containing ':focus-visible' (which short-circuits line 71 via projectHasFocusVisible) drops the same 400KB fixture from 1416ms to 9ms.

### G22 `errors.js`

**Defect.** lineOf(code, cm.index) at line 115 slices and splits the entire file prefix for every catch block, so catch-dense files cost O(catches x bytes) and cross the 1-second budget at exactly 400KB.

**Reproducer.** 400KB .js of 'try{a()}catch(e){console.log(e)}' one per line (12,122 catches); scaled 100KB / 200KB / 400KB

**Observed.** 82ms / 278ms / 1065ms — quadratic growth, over 1s at the stated 400KB budget point.

### G23 `react.js`

**Defect.** Per-effect work is quadratic: lineOf(code, em.index) at line 172 rescans the file prefix for every useEffect span, and the stale-closure branch re-runs content.matchAll for useState destructurings (lines 341-343) per []-deps effect.

**Reproducer.** 400KB .jsx of "useEffect(() => { fetch('/api/x').then(r => r.json()); setV(1); }, []);" per line (5,556 effects); scaled 100KB / 200KB / 400KB

**Observed.** 88ms / 198ms / 646ms — clear quadratic growth; 646ms at the 400KB budget point is not 'well under 1 second' and any growth past 400KB crosses it.

### G24 `async.js`

**Defect.** lineOf(code, lm.index) at line 103 plus per-loop span extraction make the await-in-loop pass quadratic in loop-dense files (O(loops x bytes)).

**Reproducer.** 400KB .js of 'for (const x of items) { await fetch(x); }' per line (9,303 loops); scaled 100KB / 200KB / 400KB

**Observed.** 72ms / 201ms / 746ms — quadratic growth; 746ms at the 400KB budget point is not 'well under 1 second'.

## Logic: false positives and structural false negatives (17)

### G1 `build-config.js`

**Defect.** probeBuildConfig throws a TypeError when the root package.json arrives with null/undefined content, violating the never-throws probe contract.

**Reproducer.** [{ path: 'package.json', content: null }] (also content: undefined)

**Observed.** TypeError: Cannot read properties of null (reading 'split') — thrown from `const lines = pkgFile.content.split('\n')` (line 91), which runs even after JSON.parse was defensively try/caught.

### G2 `react.js`

**Defect.** Check 22's path gate /(^|\/)app\/.\*(?:^|\/)(?:page|layout|template)\./ has a dead mid-pattern '^' alternative, so it requires a '/' between app/ and the filename and silently excludes the root app/page.tsx and app/layout.tsx — the most common App Router entry files.

**Reproducer.** files: next.config.js + app/page.tsx containing useState with no 'use client' (vs control app/dash/page.tsx)

**Observed.** app/page.tsx produced no react-server-clientapi finding; the identical file at app/dash/page.tsx fired at line 3.

### G3 `react.js`

**Defect.** readCallSpan counts parens inside string literals, so a ')' in any string truncates the effect span before the cleanup and a fully correct effect is flagged as leaking a listener (false positive).

**Reproducer.** useEffect(() => { window.addEventListener('resize', onR); console.log('listening :)'); return () => window.removeEventListener('resize', onR); }, [])

**Observed.** react-effect-listener fired ('Effect adds a listener it never removes') at line 3; removing the ':)' from the string yields no finding.

### G4 `react.js`

**Defect.** cleanupIsOpaque's brace scanner counts a '}' inside a string literal as closing the callback body, so a real top-level `return unsub;` cleanup after such a string is invisible and the effect is falsely flagged as never unsubscribing.

**Reproducer.** useEffect(() => { const unsub = source.subscribe(handler); console.log("depth }"); return unsub; }, [])

**Observed.** react-effect-subscription fired ('Effect subscribes and never unsubscribes'); removing the '}' from the string yields no finding.

### G5 `react.js`

**Defect.** depsOf matches the FIRST '}' followed by ',' anywhere in the span, so an object-literal declaration like `const opts = { a: 1 }, extra = 2;` inside the effect body makes deps non-null and silences check 9 (no dependency array) on an effect that has no second argument at all.

**Reproducer.** useEffect(() => { const opts = { a: 1 }, extra = 2; fetch('/api/data' + extra, opts).then(r => r.json()).then(d => setData(d)); }); // no deps arg

**Observed.** No react-effect-nodeps finding; the identical effect without the '{ a: 1 },' declaration fires at line 4.

### G6 `react.js`

**Defect.** Check 19 (index-as-key) requires the .map callback and key={i} on the same physical line, so Prettier's default multi-line JSX formatting — the dominant real-world shape — never fires it.

**Reproducer.** {items.map((item, i) => (\n <li key={i}>{item.name}</li>\n))}

**Observed.** No react-keyindex finding on the formatted version; the same JSX collapsed to one line fires (id react-keyindex-src/list.jsx-1, line 2).

### G7 `async.js`

**Defect.** loopRe's header matcher [^)]\* cannot cross the ')' of any call in the loop header, so `for (const id of getIds(list))` — an iterable produced by a call — never matches and the await-in-loop check is structurally unreachable for it.

**Reproducer.** for (const id of getIds(list)) { const r = await db.query(id); out.push(r); }

**Observed.** No async-await-in-loop finding; replacing getIds(list) with a bare identifier fires at line 3.

### G8 `errors.js`

**Defect.** catchRe's optional param group only accepts a bare \w+ identifier, so TypeScript-typed params (catch (err: unknown)) and destructured params (catch ({ message })) fail the whole match and those catch blocks are skipped by every catch-block check, including empty-catch.

**Reproducer.** src/x.ts: try { await doWork(); } catch (err: unknown) {} and try { await other(); } catch ({ message }) {}

**Observed.** Zero errors-empty-catch findings on either block; the same empty block with a plain `catch (err)` fires at line 4.

### G9 `errors.js`

**Defect.** readBraceSpan counts a '}' inside a string literal as closing the catch block, truncating the span before a `throw`, so a catch that logs then rethrows with cause is falsely reported as swallowing the error.

**Reproducer.** catch (e) { console.error("failed }", e); throw new AppError('work failed', { cause: e }); }

**Observed.** errors-catch-swallow fired (medium, 'Catch swallows the error'); removing the '}' from the log string yields no finding.

### G10 `ts-hygiene.js`

**Defect.** The file gate /@ts-|as\s+any|as\s+unknown|!\./ does not contain the non-null-chain check's own trigger (?.\w+! at end of expression), so `u?.name!` with nothing after the '!' can never be flagged.

**Reproducer.** src/a.ts: export const n = (u?: { name?: string }) => u?.name!;

**Observed.** No finding; the control `u?.name!.trim()` (which happens to contain '!.') passes the gate and fires ts-nonnull-chain.

### G11 `ts-hygiene.js`

**Defect.** The tsconfig checks test raw lines with no comment masking, so a JSONC comment mentioning the old setting fires 'tsconfig strict mode is off' on a config whose strict is actually true.

**Reproducer.** tsconfig.json: { // "strict": false was the old setting; enabled 2024-05\n "compilerOptions": { "strict": true } }

**Observed.** ts-config-tsconfig-strict-mode-is-off fired at line 2 (the comment line).

### G35 `build-config.js`

**Defect.** probeBuildConfig throws a TypeError when package.json arrives with undefined or null content, violating the never-throw probe contract.

**Reproducer.** files = [{ path: 'package.json', content: undefined }] (and content: null)

**Observed.** THREW: Cannot read properties of undefined (reading 'split') — line 91 `const lines = pkgFile.content.split('\n')` runs unconditionally after the try/catch around JSON.parse.

### G36 `react.js`

**Defect.** cleanupOf() matches a NESTED helper's `return () =>` as the effect cleanup (Gate-2 fixed only cleanupIsOpaque to require a top-level return, not cleanupOf), so code after the nested return is treated as cleanup text and a leaked listener there is exempted from check 1.

**Reproducer.** useEffect(() => { function makeHandler() { return () => console.log('tick'); } window.addEventListener('resize', makeHandler()); }, [])

**Observed.** R4a: no findings (addEventListener landed in the 'cleanup' slice). R4b control without the nested return: react-effect-listener fires.

### G37 `react.js`

**Defect.** The cheap file gate does not cover check 15's trigger: a component nested inside a component with no hook/window/map vocabulary is silently skipped, contradicting the gate's own comment 'Must cover every check's trigger'.

**Reproducer.** export function Outer() { function Inner() { return <b>x</b>; } return <Inner />; } — no useX/window/document/.map in the file.

**Observed.** R6a: no findings. R6b (same nesting plus a useState line): react-nested-component fires.

### G38 `async.js`

**Defect.** The await-in-loop regex `\b(?:for|while)\s*\([^)]*\)\s*\{` cannot match any loop whose header contains a call (nested parens), so `for (const id of Object.keys(map))` — and every Object.entries/.filter/.slice header — is structurally invisible to check 3.

**Reproducer.** for (const id of Object.keys(map)) { await fetch('/api/items/' + id); } vs control for (const id of ids) {...}

**Observed.** A1a: no findings. A1b control: async-await-in-loop fires at line 2.

### G39 `errors.js`

**Defect.** paramUses is counted on the raw (string-intact) body, contradicting the file's own Gate-2 note 'blank string literals before either test': a string containing the catch param as a hyphenated word ('e-mail') counts as a use and suppresses the swallow finding.

**Reproducer.** catch (e) { showBanner('e-mail failed'); } vs catch (e) { showBanner('mail failed'); }

**Observed.** E8a ('e-mail'): no findings. E8b ('mail'): errors-catch-swallow fires at line 4 — identical handling, the finding flips on prose inside a string.

### G40 `errors.js`

**Defect.** The catch regex `catch\s*(?:\(\s*(\w+)\s*\))?\s*\{` cannot match a TypeScript-typed catch parameter (`catch (e: unknown) {`), so EVERY catch-block check (empty catch, swallow, bare rethrow, lost stack, default return, shadow, cleanup-in-catch) is dead in the .ts/.tsx files ERRORS_FILE_RE explicitly includes.

**Reproducer.** try { doWork(); } catch (e: unknown) {} in src/f1.ts vs catch (e) {} in src/f2.ts

**Observed.** E14a typed: no findings. E14b untyped control: errors-empty-catch fires at line 4.

## Performance: superlinear scans (10)

### G25 `data-state.js`

**Defect.** probeDataState is O(n^2) on files with many fetch() calls in .jsx/.tsx: the fetch-in-render pass computes the line number with code.slice(0, idx).split('\n').length (line 211) once per fetch match, so each of N fetches re-slices+splits an ever-larger prefix of the file. This is the single worst v2 hotspot found.

**Reproducer.** [{path:'c.jsx', content:'function C(){\nconst [s]=useState();\n'+'fetch("/api/x");\n'.repeat(~24000)}] scaled to 400KB

**Observed.** 50KB 74ms, 100KB 263ms, 200KB 1024ms, 400KB 7302ms. Growth x3.6 -> x3.9 -> x7.1 for each 2x size increase; 7.3s at 400KB (findings capped at 117 while cost keeps climbing, so it is pure per-fetch overhead, not output volume).

### G26 `errors.js`

**Defect.** probeErrorHandling is O(n^2) on files with many catch blocks: the catch loop calls lineOf(code, cm.index) (const lineOf = (c,idx)=>c.slice(0,idx).split('\n').length, line 48) once per catch, re-slicing+splitting a growing prefix for each of N catches.

**Reproducer.** [{path:'e.js', content:'try{f()}catch(e){console.log(e)}\n'.repeat(~13000)}] scaled to 400KB

**Observed.** 50KB 24ms, 100KB 82ms, 200KB 314ms, 400KB 1827ms. Time grows x3.4 -> x3.8 -> x5.8 per 2x size; 1.83s at 400KB, over the 1s budget.

### G27 `react.js`

**Defect.** probeReactHygiene is O(n^2) on files with many useEffect calls: lineOf(content, em.index) (line 67, called line 172) re-slices+splits a growing prefix per effect, and the []-deps stale-closure branch additionally runs [...content.matchAll(/useState/g)] over the WHOLE file per effect (line 342). Either alone is quadratic.

**Reproducer.** non-empty-deps (isolates lineOf, 0 findings): [{path:'app.jsx', content:'const [x,setX]=useState(0);\n'+'useEffect(()=>{setX(1)},[x,y,z]);\n'.repeat(N)}]; and many-effects with body setX(1),[] to 400KB

**Observed.** non-empty deps (lineOf only, findings=0): 50KB 36ms,100KB 105ms,200KB 324ms,400KB 1291ms (x2.9/x3.1/x4.0). many-effects: 400KB 3066ms. Realistic CRLF file of ~2000 effects (~120KB): 1100ms.

### G28 `a11y-semantics.js`

**Defect.** probeA11ySemantics is O(n^2) on CSS/CSS-in-JS with many outline:none declarations: for every matching line it runs /:focus-visible/.test(code) against the entire file content (line 71), so N matching lines each scan the whole O(n) file.

**Reproducer.** [{path:'s.css', content:'.a{outline:none;}\n'.repeat(~24000)}] scaled to 400KB

**Observed.** 50KB 42ms, 100KB 148ms, 200KB 570ms, 400KB 2245ms. Time x3.6 -> x3.8 -> x3.9 per 2x size; 2.24s at 400KB, over budget.

### G29 `async.js`

**Defect.** probeAsyncCorrectness is O(n^2) on files with many loops containing awaited I/O: lineOf(code, lm.index) (line 45, called line 103) re-slices+splits a growing prefix once per loop match.

**Reproducer.** [{path:'a.js', content:'async function m(){\n'+'for(const u of us){await fetch(u)}\n'.repeat(~12000)+'}\n'}] scaled to 400KB

**Observed.** 50KB 55ms, 100KB 109ms, 200KB 333ms, 400KB 1388ms. Time x2.0 -> x3.0 -> x4.2 per 2x size; 1.39s at 400KB, over budget.

### G30 `db-patterns.js`

**Defect.** probeDbPatterns recomputes usesKnex by running /knex\s*\(|from ['"]knex['"]|require.../.test(code) against the ENTIRE file inside the per-line codeLines.forEach loop (line 115), making it O(lines * filesize) = O(n^2) even on files with zero findings and no knex.

**Reproducer.** [{path:'db.js', content:'async function w(){await prisma.a.create({});await prisma.b.create({});}\n'.repeat(N)}] scaled to 400KB (no knex present)

**Observed.** 50KB 18ms, 100KB 55ms, 200KB 205ms, 400KB 779ms, findings=0. Time x3.0 -> x3.7 -> x3.8 per 2x size: superlinear, pure overhead with no output.

### G31 `api-patterns.js`

**Defect.** probeApiPatterns is O(n^2) on files with many POST/PUT/PATCH routes: lineOf(content... code, rm.index) (line 39, called line 129) re-slices+splits a growing prefix per route match (compounded by a readBraceSpan up to 4000 chars per route).

**Reproducer.** [{path:'srv.js', content:"app.post('/login',(req,res)=>{res.json(req.body)});\n".repeat(~8000)}] scaled to 400KB

**Observed.** 50KB 27ms, 100KB 67ms, 200KB 236ms, 400KB 866ms. Time x2.5 -> x3.5 -> x3.7 per 2x size: superlinear, ~0.87s at 400KB and rising.

### G32 `data-state.js`

**Defect.** probeDataState runs a full-content regex per useState match: for each useState(props.x)/useState(x.y) line it builds and tests new RegExp('function [A-Z]...{...root...}|...').test(code) over the whole file (lines 159-161) to detect destructuring, making it O(matches \* filesize).

**Reproducer.** [{path:'c.jsx', content:'function C(props){\n'+'const [v,setV]=useState(props.value);\n'.repeat(~10000)+'return null}\n'}] scaled to 400KB

**Observed.** 50KB 20ms, 100KB 58ms, 200KB 211ms, 400KB 794ms. Time x2.9 -> x3.7 -> x3.8 per 2x size: superlinear, approaching the 1s budget at 400KB.

### G33 `react.js`

**Defect.** The array-index key check regex /\.map\s*\(\s*\(\s*\w+\s*,\s*(\w+)\s*\)\s*=>[\s\S]*?\bkey=\{\s*(\w+)\s*\}/ (lines 377-379) is quadratic on a minified single line: the .map((a,b)=> prefix matches at thousands of positions and the lazy [\s\S]\*? scans to end-of-line looking for key={ at each, so a single line.match() is O(line^2).

**Reproducer.** single line 'x.map((a,b)=>a+b);' repeated to fill 50/100/200/400KB (no key= present), measured on the regex directly and via the probe on [{path:'app.jsx', content:'const [s,setS]=useState(0);'+mapspam}]

**Observed.** regex alone: 50KB 6.5ms, 100KB 25ms, 200KB 106ms, 400KB 421ms (clean x4 per 2x size = O(n^2)). Whole probe on that file: 400KB 539ms, growth x1.3/x2.2/x3.2.

### G34 `build-config.js`

**Defect.** probeBuildConfig THROWS a TypeError when any file has an undefined path: line 37 does files.filter(...).map((f) => f.path.replace(/^\.\//, '')) with no guard, so f.path === undefined crashes the probe (and, in the real scan loop, potentially the whole scan).

**Reproducer.** [{path: undefined, content: 'x'}]

**Observed.** TypeError: Cannot read properties of undefined (reading 'replace') at src/lib/probes/v2/build-config.js:37:24 (probeBuildConfig). Every other v2 family tolerated the same input; only Build & Config threw.
