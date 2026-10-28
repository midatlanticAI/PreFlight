// src/lib/probes/v2/hallucinations.js
//
// F10: AI hallucination patterns (docs/preflight-v2-spec.md §F10, 11-probe
// roster). USENIX 2025 (Spracklen et al.): 19.7% of LLM-suggested packages
// across 576k samples did not exist. The detectable slice for a client-side
// scanner is the CLOSED vocabularies: a hook imported from 'react' that
// react has never exported is a fact, not a guess.
//
// Severity ceiling: MEDIUM — deliberately matching F7. The risk TIER takes
// the worst severity present, and a correctness finding must not brand a
// repo HIGH RISK (pinned by calibration-acceptance-v1). Whether health-axis
// findings should ever reach high is the parked class-ceiling decision;
// until it is made, these families teach at medium and below.
// resolves to a squatted package — health axis, but the squat risk is why
// the ceiling is high).
//
// Roster entries deliberately not built, with reasons:
//   unknown_npm_import — needs a registry snapshot; the curated
//       compromised-packages manifest deliberately is not one, and the
//       supply-chain probe already owns slopsquatting shapes.
//   hallucinated_tailwind_class / css_property / browser_api / env_var /
//   framework_config_option — open vocabularies (plugins, custom
//       properties, vendor APIs); a closed-list check would false-positive
//       on every legitimate extension.
//   hallucinated_type_import — type-only facts need the checker.

import { isTestFile, isScannerSelfSource } from '../../file-filter.js';
import { maskCommentsForPath } from '../_internal/masking.js';

export const HALLUCINATION_FILE_RE = /\.(?:[jt]sx?|mjs|cjs)$/i;

// Every value export of react 18/19 (hooks and top-level API).
export const REACT_EXPORTS = new Set([
  'Children',
  'Component',
  'Fragment',
  'Profiler',
  'PureComponent',
  'StrictMode',
  'Suspense',
  'cloneElement',
  'createContext',
  'createElement',
  'createFactory',
  'createRef',
  'forwardRef',
  'isValidElement',
  'lazy',
  'memo',
  'startTransition',
  'unstable_act',
  'act',
  'cache',
  'use',
  'useCallback',
  'useContext',
  'useDebugValue',
  'useDeferredValue',
  'useEffect',
  'useId',
  'useImperativeHandle',
  'useInsertionEffect',
  'useLayoutEffect',
  'useMemo',
  'useOptimistic',
  'useReducer',
  'useRef',
  'useState',
  'useSyncExternalStore',
  'useTransition',
  'useActionState',
  'version',
  // React 19.1/19.2 (verified against the react.dev release posts, Gate-1):
  'Activity',
  'useEffectEvent',
  'cacheSignal',
  'captureOwnerStack',
  'experimental_useEffectEvent',
]);

// Prisma client model delegate methods (the complete public set).
export const PRISMA_MODEL_METHODS = new Set([
  'findUnique',
  'findUniqueOrThrow',
  'findFirst',
  'findFirstOrThrow',
  'findMany',
  'create',
  'createMany',
  'createManyAndReturn',
  'update',
  'updateMany',
  'updateManyAndReturn',
  'upsert',
  'delete',
  'deleteMany',
  'count',
  'aggregate',
  'groupBy',
  'fields',
  // MongoDB datasource delegates (prisma.io raw-queries docs, Gate-1):
  'findRaw',
  'aggregateRaw',
]);

// next/navigation value exports (App Router).
export const NEXT_NAVIGATION_EXPORTS = new Set([
  'useRouter',
  'usePathname',
  'useSearchParams',
  'useParams',
  'useSelectedLayoutSegment',
  'useSelectedLayoutSegments',
  'useServerInsertedHTML',
  'redirect',
  'permanentRedirect',
  'notFound',
  'forbidden',
  'unauthorized',
  'ServerInsertedHTMLContext',
  'RedirectType',
  'unstable_rethrow',
  'ReadonlyURLSearchParams',
]);

const finding = (o) => ({
  probe: 'AI Hallucinations',
  category: 'Code Correctness',
  severity: 'medium',
  cwe: 'CWE-1357',
  ...o,
});

export function probeAiHallucinations(files) {
  const findings = [];
  // Gate-1: prisma.$extends model extensions add custom delegate methods by
  // design (stable since Prisma 4.16); when any file defines extensions,
  // unknown method names are the feature, not a hallucination.
  const projectUsesExtends = files.some((f) => /\$extends\s*\(/.test(f.content || ''));
  // Gate-2 (C18): the client is whatever the author NAMED it — `const db =
  // new PrismaClient()` hides every invented delegate method from a check
  // that only reads `prisma.`. Exported client names count in files that
  // import them; local instantiations count in their own file.
  const exportedClients = new Set();
  files.forEach((f) => {
    for (const m of (f.content || '').matchAll(
      /export\s+(?:const|let|var)\s+(\w+)\s*=\s*new\s+PrismaClient\s*\(/g
    ))
      exportedClients.add(m[1]);
  });
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!HALLUCINATION_FILE_RE.test(file.path)) return;
    const content = file.content || '';
    if (!content.trim()) return;
    const clientNames = new Set(['prisma']);
    for (const m of content.matchAll(/(?:const|let|var)\s+(\w+)\s*=\s*new\s+PrismaClient\s*\(/g))
      clientNames.add(m[1]);
    for (const name of exportedClients) {
      if (
        new RegExp(`import\\s*\\{[^}]*\\b${name}\\b[^}]*\\}|import\\s+${name}\\s+from`).test(
          content
        )
      )
        clientNames.add(name);
    }
    const prismaDelegateRe = new RegExp(
      `\\b(${[...clientNames].join('|')})\\.(\\w+)\\.(\\w+)\\s*\\(`
    );
    if (
      !new RegExp(`from\\s+['"](?:react|next\\/navigation)['"]`).test(content) &&
      !prismaDelegateRe.test(content)
    )
      return;
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
      // Named imports from 'react' that react does not export.
      // Bounded: `[^}]+` rescanned to end-of-line from every `import {` on a
      // brace-free minified line (Gate-3 G18).
      const rm = line.match(/import\s*\{([^}]{1,600})\}\s*from\s*['"]react['"]/);
      if (rm) {
        const isTs = /\.(?:ts|tsx|mts|cts)$/i.test(file.path);
        for (const raw of rm[1].split(',')) {
          const name = raw
            .trim()
            .split(/\s+as\s+/)[0]
            .trim();
          // Gate-1: in TypeScript, plain named imports of react's TYPE
          // exports (FC, ReactNode, Dispatch, SetStateAction, …) are legal
          // and elided by the compiler — the type universe is open, so on
          // .ts/.tsx only invented HOOKS (lowercase use*) are closed-world.
          if (isTs && !/^use[A-Z]/.test(name)) continue;
          if (name && !REACT_EXPORTS.has(name) && !/^type\s/.test(raw.trim())) {
            push(i, {
              id: `halluc-react-${file.path}-${i}-${name}`,
              title: `'${name}' is not exported by react`,
              severity: 'medium',
              remediation: `react has never exported ${name}; the import is undefined at runtime and calling it throws. If it is a data hook you wanted, it lives in a library (TanStack Query, SWR) or you write it — and if a suggestion invents a package by this name, do not install it: invented names are exactly what squatters register.`,
            });
          }
        }
      }
      // Named imports from 'next/navigation' outside its export list.
      const nm = line.match(/import\s*\{([^}]{1,600})\}\s*from\s*['"]next\/navigation['"]/);
      if (nm) {
        for (const raw of nm[1].split(',')) {
          const name = raw
            .trim()
            .split(/\s+as\s+/)[0]
            .trim();
          if (name && !NEXT_NAVIGATION_EXPORTS.has(name) && !/^type\s/.test(raw.trim())) {
            push(i, {
              id: `halluc-next-${file.path}-${i}-${name}`,
              title: `'${name}' is not exported by next/navigation`,
              severity: 'medium',
              remediation: `next/navigation does not export ${name}. Check the Next.js App Router docs for the real name — the Pages Router equivalents live in next/router, and mixing the two is the usual source of invented ones.`,
            });
          }
        }
      }
      // Prisma delegate methods that do not exist.
      const pm = line.match(prismaDelegateRe);
      if (
        pm &&
        !projectUsesExtends &&
        !pm[2].startsWith('$') &&
        !PRISMA_MODEL_METHODS.has(pm[3]) &&
        !pm[3].startsWith('$')
      ) {
        push(i, {
          id: `halluc-prisma-${file.path}-${i}-${pm[3]}`,
          title: `${pm[1]}.${pm[2]}.${pm[3]} is not a Prisma client method`,
          severity: 'medium',
          remediation: `Model delegates expose a fixed set (findUnique, findFirst, findMany, create, update, upsert, delete, count, aggregate, groupBy and their variants); ${pm[3]} is not in it, so this throws at runtime. The usual intended spellings: findOneOrThrow → findUniqueOrThrow, insert → create, remove → delete.`,
        });
      }
    });
  });
  return findings;
}
