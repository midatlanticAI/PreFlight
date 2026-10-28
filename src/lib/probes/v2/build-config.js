// src/lib/probes/v2/build-config.js
//
// F9: Build, config and dependency smells (docs/preflight-v2-spec.md §F9,
// 12-probe roster). The project-level facts that decide whether "works on my
// machine" survives contact with a second machine.
//
// Severity ceiling: MEDIUM (health axis).
//
// Roster entries deliberately not built, with reasons:
//   eslint_disabling_core_rules — which rules a project disables is a
//       judgment call; AI Codegen Bloat already flags per-line
//       eslint-disable with no justification.
//   outdated_framework_major / peer_dependencies_not_satisfied — need the
//       registry and a resolver; a static scan would be guessing versions.
//   tsconfig_strict_false — owned by TypeScript Hygiene.
//   missing_nvmrc — engines in package.json (checked here) is the portable
//       spelling of the same intent; flagging both is one lesson twice.

import { isEnvTemplateFile } from '../../file-filter.js';

const finding = (o) => ({
  probe: 'Build & Config',
  category: 'Maintainability',
  severity: 'medium',
  cwe: 'CWE-1357',
  ...o,
});

export function probeBuildConfig(files) {
  const findings = [];
  // Gate-1: folder uploads arrive with the selected directory's name
  // prefixed to EVERY path (webkitRelativePath), which broke every
  // exact-match root check — a committed lockfile read as missing on
  // essentially all folder-uploaded projects. Strip the shared root.
  // Gate-3 G34: a record with no path threw here and took the whole family
  // down for the scan. The contract is never throw; a pathless record is
  // simply not a path.
  const rawPaths = files
    .filter((f) => f && typeof f.path === 'string' && !/node_modules/.test(f.path))
    .map((f) => f.path.replace(/^\.\//, ''));
  const firstSeg = rawPaths.length && rawPaths[0].includes('/') ? rawPaths[0].split('/')[0] : null;
  const sharedRoot =
    firstSeg && rawPaths.every((p) => p === firstSeg || p.startsWith(firstSeg + '/'))
      ? firstSeg + '/'
      : '';
  const norm = (p) => (sharedRoot && p.startsWith(sharedRoot) ? p.slice(sharedRoot.length) : p);
  const paths = new Set(rawPaths.map(norm));
  const rootHas = (name) => paths.has(name);
  // Gate-1: monorepos list workspace members before the root; the ROOT
  // manifest (shortest normalized path) is the one that speaks for the
  // project's lockfile, engines, and scripts.
  const pkgCandidates = files
    .filter((f) => /(^|\/)package\.json$/.test(f.path) && !/node_modules/.test(f.path))
    .sort((a, b) => norm(a.path).split('/').length - norm(b.path).split('/').length);
  const pkgFile = pkgCandidates[0];

  // Mixed lockfiles: two package managers both think they own the install.
  const LOCKS_BY_MANAGER = {
    npm: ['package-lock.json'],
    yarn: ['yarn.lock'],
    pnpm: ['pnpm-lock.yaml'],
    bun: ['bun.lock', 'bun.lockb'],
  };
  const locks = Object.values(LOCKS_BY_MANAGER)
    .flat()
    .filter((l) => rootHas(l));
  // Gate-1: bun keeps bun.lock AND bun.lockb through its text-lockfile
  // migration — two spellings, one manager. Count MANAGERS, not files.
  const lockManagers = Object.entries(LOCKS_BY_MANAGER)
    .filter(([, names]) => names.some((l) => rootHas(l)))
    .map(([m]) => m);
  if (lockManagers.length >= 2) {
    findings.push(
      finding({
        id: `build-mixed-locks-${locks[0]}`,
        title: `Lockfiles from ${lockManagers.length} different package managers`,
        severity: 'medium',
        file: locks[1],
        line: 1,
        evidence: locks.join(', '),
        remediation:
          'Whichever manager runs second installs from its own lockfile and ignores the other, so two machines "installing the same project" can hold different trees. Pick one manager, delete the other lockfiles, and add a packageManager field to package.json so the choice is enforced.',
      })
    );
  }

  if (pkgFile) {
    // Gate-3 G12/G35: null or undefined content survived the JSON.parse
    // try/catch and threw on .split one line later.
    const pkgText = typeof pkgFile.content === 'string' ? pkgFile.content : '';
    let pkg = null;
    try {
      pkg = JSON.parse(pkgText);
    } catch {
      pkg = null; // malformed package.json is its own concern, not this one
    }
    const lines = pkgText.split('\n');
    const lineFor = (needle) => {
      const i = lines.findIndex((l) => l.includes(needle));
      return i === -1 ? 1 : i + 1;
    };
    if (pkg) {
      // No lockfile at all: every install resolves fresh.
      if (locks.length === 0 && (pkg.dependencies || pkg.devDependencies)) {
        findings.push(
          finding({
            id: `build-no-lockfile-${pkgFile.path}`,
            title: 'No lockfile committed',
            severity: 'medium',
            file: pkgFile.path,
            line: 1,
            evidence:
              'package.json has dependencies; no package-lock.json / yarn.lock / pnpm-lock.yaml / bun.lock in the scan',
            remediation:
              "Without a lockfile every install re-resolves every range, so today's deploy and last week's can run different code — including a compromised patch release published in between. Commit the lockfile your manager writes and install with npm ci (or the equivalent) in CI.",
          })
        );
      }
      // engines missing: Node version is whatever the machine happens to run.
      const anyEngines = pkgCandidates.some((f) => {
        try {
          return Boolean(JSON.parse(f.content || '{}').engines?.node);
        } catch {
          return false;
        }
      });
      if (!anyEngines && (pkg.dependencies || pkg.scripts)) {
        findings.push(
          finding({
            id: `build-no-engines-${pkgFile.path}`,
            title: 'package.json declares no Node engines range',
            severity: 'low',
            file: pkgFile.path,
            line: 1,
            evidence: 'no "engines": { "node": … } field',
            remediation:
              'The project runs on whatever Node the machine has, and the failure mode is a syntax error or a subtle API difference on someone else\'s laptop or CI image. Declare "engines": { "node": ">=20" } and CI images and teammates converge on it.',
          })
        );
      }
      // @types/* and build tooling in runtime dependencies.
      const deps = Object.keys(pkg.dependencies || {});
      const runtimeScript = [pkg.scripts?.start, pkg.scripts?.serve, pkg.main]
        .filter(Boolean)
        .join(' ');
      const misfiled = deps.filter(
        (d) =>
          // Gate-2 (C28): the CSS/build toolchain rides in dependencies just
          // as often — tailwind, postcss, sass, bundler plugins, babel
          // tooling (@babel/runtime is the one @babel/* that IS runtime).
          /^@types\/|^typescript$|^vite$|^webpack$|^eslint|^prettier$|^vitest$|^jest$|^ts-node$|^tailwindcss$|^postcss$|^autoprefixer$|^sass$|^esbuild$|^rollup$|^@vitejs\/|^@babel\/(?!runtime)/.test(
            d
          ) &&
          // Gate-1: a ts-node production runtime NEEDS ts-node (and
          // typescript) at runtime; moving them breaks npm ci --omit=dev.
          !(runtimeScript.includes(d) || (d === 'typescript' && /ts-node/.test(runtimeScript)))
      );
      if (misfiled.length) {
        findings.push(
          finding({
            id: `build-misfiled-deps-${pkgFile.path}`,
            title: `${misfiled.length} build-time package${misfiled.length === 1 ? '' : 's'} in dependencies`,
            severity: 'low',
            file: pkgFile.path,
            line: lineFor(misfiled[0]),
            evidence: misfiled.join(', '),
            remediation:
              'Runtime dependencies are what production installs; type packages and build tools there mean heavier deploys and, on some hosts, longer cold starts. Move them to devDependencies: npm install -D ' +
              misfiled.join(' ') +
              '.',
          })
        );
      }
      // Build script that swallows its own failure.
      for (const [name, script] of Object.entries(pkg.scripts || {})) {
        // Gate-1: "prepare": "husky || true" is husky's own documented
        // spelling so production installs without devDependencies succeed.
        if (name === 'prepare' && /husky/.test(String(script))) continue;
        // Gate-2 (C31): `|| echo "build failed"` and the shell no-op `|| :`
        // swallow the exit code the same way || true does.
        if (
          typeof script === 'string' &&
          /\|\|\s*(?:true\b|exit 0\b|echo\b|:(?:\s|$))/.test(script)
        ) {
          findings.push(
            finding({
              id: `build-or-true-${pkgFile.path}-${name}`,
              title: `Script "${name}" ignores its own failure`,
              severity: 'medium',
              file: pkgFile.path,
              line: lineFor(`"${name}"`),
              evidence: `${name}: ${script}`.slice(0, 160),
              remediation:
                '|| true converts a failing build into a green one, so CI ships whatever the failure left behind. Remove it and let the failure fail; if one step is genuinely optional, isolate that step and say why in the script name.',
            })
          );
        }
      }
    }
    // .env ignored but no .env.example: the next developer gets a crash
    // with no map of what to set.
    const gitignore = files.find((f) => /(^|\/)\.gitignore$/.test(f.path));
    // Gate-1: reuse the file-filter's template vocabulary — F9 had
    // reimplemented it narrowly and missed .env.local.example/.env-example,
    // forms isEnvTemplateFile already accepts from a real user hit.
    const hasEnvExample = [...paths].some((p) => isEnvTemplateFile(p));
    if (
      gitignore &&
      /^\s*\.env/m.test(gitignore.content || '') &&
      !hasEnvExample &&
      files.some((f) => /process\.env\.[A-Z]/.test(f.content || ''))
    ) {
      findings.push(
        finding({
          id: `build-no-env-example-${gitignore.path}`,
          title: '.env is ignored but no .env.example documents it',
          severity: 'low',
          file: gitignore.path,
          line: 1,
          evidence: '.gitignore excludes .env; no .env.example in the scan; code reads process.env',
          remediation:
            'Ignoring .env is right; the missing half is the map. Commit a .env.example with every variable name and a placeholder value, so the next clone fails with a checklist instead of a mystery.',
        })
      );
    }
    // Two frameworks' config files at once.
    let fwConfigs = [
      'next.config.js',
      'next.config.mjs',
      'gatsby-config.js',
      'nuxt.config.ts',
      'remix.config.js',
      'astro.config.mjs',
      'svelte.config.js',
    ].filter((c) => rootHas(c));
    // Gate-1: Astro's official UI integrations READ svelte.config.js by
    // design — that pairing is one framework's setup, not a stalled
    // migration.
    if (fwConfigs.includes('astro.config.mjs')) {
      fwConfigs = fwConfigs.filter((c) => c !== 'svelte.config.js');
    }
    if (fwConfigs.length >= 2) {
      findings.push(
        finding({
          id: `build-fw-conflict-${fwConfigs[0]}`,
          title: `Config files for ${fwConfigs.length} different frameworks`,
          severity: 'medium',
          file: fwConfigs[1],
          line: 1,
          evidence: fwConfigs.join(', '),
          remediation:
            "Two frameworks' configs in one root usually means a migration that stopped halfway; tooling, deploy targets and AI assistants will each pick a different one to believe. Finish the migration and delete the loser's config.",
        })
      );
    }
  }
  return findings;
}
