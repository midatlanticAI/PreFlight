// Adversarial PRECISION suite, round 1: compromised-package probe must NOT fire.
//
// Every input below is benign. Each one is shaped to look like a compromised-package
// reference (adjacent versions, lookalike names, version strings in the wrong field,
// lockfile noise) without actually containing a known-compromised resolution.
// A naive scanner over-fires on these. The probe should return zero findings.
//
// Written without reading the probe implementation or its manifest, on purpose:
// these tests encode the external contract, not the internals.

import { describe, it, expect } from 'vitest';
import { probeCompromisedPackages } from '../lib/probes.js';

// ---------- helpers ----------

const f = (path, content) => ({ path, content });

const pkg = (obj, path = 'package.json') => f(path, JSON.stringify(obj, null, 2));

const expectClean = (files) => {
  const findings = probeCompromisedPackages(files);
  expect(findings).toEqual([]);
};

// A realistic baseline manifest that safe fixtures build on.
const base = (extra = {}) => ({
  name: 'benign-app',
  version: '1.0.0',
  private: true,
  ...extra,
});

// ---------- 1. safe adjacent versions ----------

describe('precision: safe adjacent versions of flagged packages', () => {
  it('does not flag axios pinned to 1.14.0 (one patch below the bad version)', () => {
    expectClean([pkg(base({ dependencies: { axios: '1.14.0' } }))]);
  });

  it('does not flag axios pinned to 1.14.2 (one patch above the bad version)', () => {
    expectClean([pkg(base({ dependencies: { axios: '1.14.2' } }))]);
  });

  it('does not flag axios pinned to 1.15.1 (next minor line)', () => {
    expectClean([pkg(base({ dependencies: { axios: '1.15.1' } }))]);
  });

  it('does not flag axios pinned to 0.30.3 (old major line, same digits shuffled)', () => {
    expectClean([pkg(base({ dependencies: { axios: '0.30.3' } }))]);
  });

  it('does not flag @tanstack/react-router pinned far below the bad version', () => {
    expectClean([pkg(base({ dependencies: { '@tanstack/react-router': '1.100.0' } }))]);
  });

  it('does not flag a mix of flagged package names all pinned to safe versions', () => {
    expectClean([
      pkg(
        base({
          dependencies: {
            axios: '1.15.1',
            '@tanstack/react-router': '1.100.0',
          },
          devDependencies: {
            'intercom-client': '5.0.0',
          },
        })
      ),
    ]);
  });
});

// ---------- 2. ranges that exclude the bad version ----------

describe('precision: semver ranges that exclude the compromised version', () => {
  it('does not flag axios "~1.13.0" (tilde range below 1.14.x)', () => {
    expectClean([pkg(base({ dependencies: { axios: '~1.13.0' } }))]);
  });

  it('does not flag axios "^0.29.0" (caret range in the 0.x line)', () => {
    expectClean([pkg(base({ dependencies: { axios: '^0.29.0' } }))]);
  });

  // Round-1 adjudication: "<1.14.0" was authored to exclude 1.14.1, but
  // axios ALSO has a second compromised release at 0.30.4 (unknown to the
  // test author's brief) and the open lower bound includes it — the probe
  // was right to fire. Rewritten with a floor that excludes both.
  it('does not flag axios ">0.30.4 <1.14.0" (bounded between the two bad versions)', () => {
    expectClean([pkg(base({ dependencies: { axios: '>0.30.4 <1.14.0' } }))]);
  });

  it('does not flag axios "1.13.x" (x-range one minor below)', () => {
    expectClean([pkg(base({ dependencies: { axios: '1.13.x' } }))]);
  });

  it('does not flag axios ">=1.15.0 <2.0.0" (window starting above the bad version)', () => {
    expectClean([pkg(base({ dependencies: { axios: '>=1.15.0 <2.0.0' } }))]);
  });

  it('does not flag axios "~1.15.1" (tilde range above the bad version)', () => {
    expectClean([pkg(base({ dependencies: { axios: '~1.15.1' } }))]);
  });
});

// ---------- 3. similarly-named but different packages ----------

describe('precision: lookalike package names that are not the flagged package', () => {
  it('does not flag axios-retry at the bad-looking version number', () => {
    // Different package entirely; the version digits are a coincidence.
    expectClean([pkg(base({ dependencies: { 'axios-retry': '1.14.1' } }))]);
  });

  it('does not flag axios-mock-adapter', () => {
    expectClean([pkg(base({ devDependencies: { 'axios-mock-adapter': '1.14.1' } }))]);
  });

  it('does not flag a scoped @myco/axios fork at the bad version number', () => {
    // Scope changes identity. @myco/axios is not axios.
    expectClean([pkg(base({ dependencies: { '@myco/axios': '1.14.1' } }))]);
  });

  it('does not flag plain react-router at the @tanstack/react-router bad version', () => {
    // react-router (Remix) and @tanstack/react-router are unrelated packages.
    expectClean([pkg(base({ dependencies: { 'react-router': '1.169.5' } }))]);
  });

  it('does not flag @tanstack/react-query at the react-router bad version', () => {
    // Same scope, different package.
    expectClean([pkg(base({ dependencies: { '@tanstack/react-query': '1.169.5' } }))]);
  });

  it('does not flag unscoped bitwarden lookalikes at the @bitwarden/cli bad version', () => {
    expectClean([
      pkg(base({ dependencies: { bitwarden: '2026.4.0', 'bitwarden-cli': '2026.4.0' } })),
    ]);
  });
});

// ---------- 4. version strings in non-dependency fields ----------

describe('precision: bad-version-shaped strings in other package.json fields', () => {
  it('does not flag a bad version string in the description field', () => {
    expectClean([
      pkg(
        base({
          description: 'Internal tooling. We skipped axios 1.14.1 during the supply-chain scare.',
          dependencies: { axios: '1.15.1' },
        })
      ),
    ]);
  });

  it('does not flag a bad version string inside a scripts entry', () => {
    expectClean([
      pkg(
        base({
          scripts: {
            'check:axios': 'npm ls axios@1.14.1 && exit 1 || exit 0',
            postinstall: 'node scripts/verify-no-intercom-client-7.0.4.mjs',
          },
        })
      ),
    ]);
  });

  it('does not flag version-shaped strings in repository / homepage / keywords', () => {
    expectClean([
      pkg(
        base({
          repository: {
            type: 'git',
            url: 'https://github.com/example/audit-notes/tree/axios-1.14.1-postmortem',
          },
          homepage: 'https://example.com/blog/tanstack-react-router-1.169.5-incident',
          keywords: ['axios', '1.14.1', 'supply-chain', 'postmortem'],
        })
      ),
    ]);
  });

  it('does not flag a bad version string in the config or engines blocks', () => {
    expectClean([
      pkg(
        base({
          engines: { node: '>=18' },
          config: { blockedVersions: 'axios@1.14.1,intercom-client@7.0.4' },
        })
      ),
    ]);
  });
});

// ---------- 5. lockfiles resolving to safe versions, every format ----------

describe('precision: lockfiles that resolve flagged names to safe versions', () => {
  it('does not flag an npm v3 lockfile resolving axios to 1.15.1', () => {
    expectClean([
      pkg(base({ dependencies: { axios: '^1.15.0' } })),
      f(
        'package-lock.json',
        JSON.stringify(
          {
            name: 'benign-app',
            version: '1.0.0',
            lockfileVersion: 3,
            requires: true,
            packages: {
              '': { name: 'benign-app', dependencies: { axios: '^1.15.0' } },
              'node_modules/axios': {
                version: '1.15.1',
                resolved: 'https://registry.npmjs.org/axios/-/axios-1.15.1.tgz',
                integrity: 'sha512-deadbeef',
              },
            },
          },
          null,
          2
        )
      ),
    ]);
  });

  it('does not flag a legacy npm v1 lockfile resolving axios to 1.14.0', () => {
    expectClean([
      f(
        'package-lock.json',
        JSON.stringify(
          {
            name: 'benign-app',
            version: '1.0.0',
            lockfileVersion: 1,
            requires: true,
            dependencies: {
              axios: {
                version: '1.14.0',
                resolved: 'https://registry.npmjs.org/axios/-/axios-1.14.0.tgz',
                integrity: 'sha512-cafef00d',
              },
            },
          },
          null,
          2
        )
      ),
    ]);
  });

  it('does not flag a yarn v1 lockfile resolving axios to 1.15.1', () => {
    expectClean([
      f(
        'yarn.lock',
        [
          '# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.',
          '# yarn lockfile v1',
          '',
          'axios@^1.15.0, axios@~1.15.1:',
          '  version "1.15.1"',
          '  resolved "https://registry.yarnpkg.com/axios/-/axios-1.15.1.tgz#abc123"',
          '  integrity sha512-deadbeef',
          '',
        ].join('\n')
      ),
    ]);
  });

  it('does not flag a pnpm lockfile resolving axios to 1.15.1', () => {
    expectClean([
      f(
        'pnpm-lock.yaml',
        [
          "lockfileVersion: '9.0'",
          '',
          'settings:',
          '  autoInstallPeers: true',
          '  excludeLinksFromLockfile: false',
          '',
          'importers:',
          '  .:',
          '    dependencies:',
          '      axios:',
          '        specifier: ^1.15.0',
          '        version: 1.15.1',
          '',
          'packages:',
          '  axios@1.15.1:',
          '    resolution: {integrity: sha512-deadbeef}',
          '',
        ].join('\n')
      ),
    ]);
  });

  it('does not flag a bun lockfile resolving axios to 1.15.1', () => {
    expectClean([
      f(
        'bun.lock',
        JSON.stringify(
          {
            lockfileVersion: 1,
            workspaces: {
              '': { name: 'benign-app', dependencies: { axios: '^1.15.0' } },
            },
            packages: {
              axios: ['axios@1.15.1', '', {}, 'sha512-deadbeef'],
            },
          },
          null,
          2
        )
      ),
    ]);
  });

  it('does not flag safe transitive resolutions of multiple flagged names (npm v3)', () => {
    expectClean([
      f(
        'package-lock.json',
        JSON.stringify(
          {
            lockfileVersion: 3,
            packages: {
              '': { name: 'benign-app' },
              'node_modules/axios': { version: '1.14.2' },
              'node_modules/@tanstack/react-router': { version: '1.100.0' },
              'node_modules/intercom-client': { version: '5.0.0' },
              'node_modules/some-sdk/node_modules/axios': { version: '1.15.1' },
            },
          },
          null,
          2
        )
      ),
    ]);
  });
});

// ---------- 6. lockfile keys that look like package paths but are not ----------

describe('precision: lockfile noise that resembles package descriptors', () => {
  it('does not flag bad versions mentioned only in yarn.lock comment lines', () => {
    expectClean([
      f(
        'yarn.lock',
        [
          '# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.',
          '# yarn lockfile v1',
          '# NOTE: axios@1.14.1 was purged from this tree on 2026-01-12.',
          '# See incident notes for intercom-client@7.0.4.',
          '',
          'axios@^1.15.0:',
          '  version "1.15.1"',
          '  resolved "https://registry.yarnpkg.com/axios/-/axios-1.15.1.tgz#abc123"',
          '',
        ].join('\n')
      ),
    ]);
  });

  it('does not flag pnpm settings / metadata keys that look like package paths', () => {
    expectClean([
      f(
        'pnpm-lock.yaml',
        [
          "lockfileVersion: '9.0'",
          '',
          'settings:',
          '  autoInstallPeers: true',
          '  excludeLinksFromLockfile: false',
          '',
          'overrides:',
          "  'axios@<1.15.0': 1.15.1",
          '',
          'patchedDependencies:',
          '  axios@1.15.1:',
          '    hash: abc123',
          '    path: patches/axios@1.15.1.patch',
          '',
          'importers:',
          '  .:',
          '    dependencies:',
          '      axios:',
          '        specifier: ^1.15.0',
          '        version: 1.15.1',
          '',
        ].join('\n')
      ),
    ]);
  });

  it('does not flag yarn berry metadata blocks and cache keys', () => {
    expectClean([
      f(
        'yarn.lock',
        [
          '# This file is generated by running "yarn install" inside your project.',
          '# Manual changes might be lost - proceed with caution!',
          '',
          '__metadata:',
          '  version: 8',
          '  cacheKey: 10c0',
          '',
          '"axios@npm:^1.15.0":',
          '  version: 1.15.1',
          '  resolution: "axios@npm:1.15.1"',
          '  checksum: 10c0/deadbeef',
          '  languageName: node',
          '  linkType: hard',
          '',
        ].join('\n')
      ),
    ]);
  });
});

// ---------- 7. version-shaped strings in source and docs files ----------

describe('precision: bad versions mentioned in source, docs, and changelogs', () => {
  it('does not flag "axios@1.14.1" in a JS comment', () => {
    expectClean([
      f(
        'src/api.js',
        [
          '// TODO: keep the floor above axios@1.14.1, that release was pulled.',
          "import axios from 'axios';",
          'export const client = axios.create({ timeout: 5000 });',
          '',
        ].join('\n')
      ),
    ]);
  });

  it('does not flag bad versions listed in a CHANGELOG', () => {
    expectClean([
      f(
        'CHANGELOG.md',
        [
          '# Changelog',
          '',
          '## 2.1.0',
          '',
          '- Bumped axios from 1.14.1 to 1.15.1 after the registry advisory.',
          '- Verified we never shipped intercom-client 7.0.4 or @bitwarden/cli 2026.4.0.',
          '',
        ].join('\n')
      ),
    ]);
  });

  it('does not flag bad-version string literals in TS source', () => {
    expectClean([
      f(
        'src/security/blocklist.ts',
        [
          '// Local denylist used by our own install-time check.',
          'export const BLOCKED_SPECS: string[] = [',
          "  'axios@1.14.1',",
          "  '@tanstack/react-router@1.169.5',",
          "  'intercom-client@7.0.4',",
          '];',
          '',
        ].join('\n')
      ),
    ]);
  });

  it('does not flag a JSON data file that is not a manifest or lockfile', () => {
    expectClean([
      f(
        'src/data/advisory-notes.json',
        JSON.stringify({ dependencies: { axios: '1.14.1' }, note: 'quiz fixture, not a manifest' })
      ),
    ]);
  });
});

// ---------- 8. malformed / empty / non-JSON manifests and lockfiles ----------

describe('precision: malformed inputs must not crash or flag', () => {
  it('handles an empty package.json', () => {
    expectClean([f('package.json', '')]);
  });

  it('handles truncated / invalid JSON in package.json', () => {
    expectClean([f('package.json', '{ "name": "benign-app", "dependencies": { "axios": ')]);
  });

  it('handles a package.json whose root is not an object', () => {
    expectClean([f('package.json', '["axios", "1.14.1"]')]);
  });

  it('handles a package-lock.json that is not JSON at all', () => {
    expectClean([f('package-lock.json', 'PK not actually json  ')]);
  });

  it('handles an empty yarn.lock and an empty pnpm-lock.yaml', () => {
    expectClean([f('yarn.lock', ''), f('pnpm-lock.yaml', '')]);
  });

  it('handles dependency maps with non-string junk values', () => {
    expectClean([
      f(
        'package.json',
        JSON.stringify({
          name: 'benign-app',
          dependencies: { axios: null, lodash: 42, react: { weird: true } },
        })
      ),
    ]);
  });
});

// ---------- 9. git / file / workspace dep specs ----------

describe('precision: non-registry dependency specifiers on benign packages', () => {
  it('does not flag file: and link: specs', () => {
    expectClean([
      pkg(
        base({
          dependencies: {
            'my-local-lib': 'file:../my-local-lib',
            'design-tokens': 'link:./packages/design-tokens',
          },
        })
      ),
    ]);
  });

  it('does not flag workspace: protocol specs', () => {
    expectClean([
      pkg(
        base({
          dependencies: { '@app/shared': 'workspace:*', '@app/ui': 'workspace:^' },
        })
      ),
    ]);
  });

  it('does not flag git specs even when the ref looks like a bad version', () => {
    // The #v1.14.1 tag lives on an unrelated internal package, not axios.
    expectClean([
      pkg(
        base({
          dependencies: {
            'internal-utils': 'git+https://github.com/example/internal-utils.git#v1.14.1',
            'left-pad-fork': 'github:example/left-pad-fork#semver:^1.3.0',
          },
        })
      ),
    ]);
  });
});

// ---------- 10. devDependencies on safe versions of flagged names ----------

describe('precision: devDependencies pinned to safe versions of flagged names', () => {
  it('does not flag axios 1.15.1 in devDependencies', () => {
    expectClean([pkg(base({ devDependencies: { axios: '1.15.1' } }))]);
  });

  it('does not flag @tanstack/react-router on a safe version in devDependencies', () => {
    expectClean([pkg(base({ devDependencies: { '@tanstack/react-router': '1.100.0' } }))]);
  });

  it('does not flag safe versions across dev, peer, and optional dependency blocks', () => {
    expectClean([
      pkg(
        base({
          devDependencies: { axios: '1.14.0' },
          peerDependencies: { axios: '>=1.15.0' },
          optionalDependencies: { 'intercom-client': '5.0.0' },
        })
      ),
    ]);
  });
});

// ---------- 11. vendored node_modules manifests with safe contents ----------

describe('precision: package.json files under node_modules with safe contents', () => {
  it('does not flag a vendored axios manifest at a safe version', () => {
    expectClean([
      pkg(
        { name: 'axios', version: '1.15.1', main: 'index.js' },
        'node_modules/axios/package.json'
      ),
    ]);
  });

  it('does not flag a vendored dependency that itself depends on safe axios', () => {
    expectClean([
      pkg(
        { name: 'some-sdk', version: '3.2.0', dependencies: { axios: '^1.15.0' } },
        'node_modules/some-sdk/package.json'
      ),
    ]);
  });

  it('does not flag deeply nested vendored manifests with safe contents', () => {
    expectClean([
      pkg(
        { name: 'axios', version: '1.14.2' },
        'node_modules/some-sdk/node_modules/axios/package.json'
      ),
      pkg(
        { name: '@tanstack/react-router', version: '1.100.0' },
        'node_modules/@tanstack/react-router/package.json'
      ),
    ]);
  });
});

// ---------- 12. substring / superstring name collisions ----------

describe('precision: names that are substrings or superstrings of flagged names', () => {
  it('does not flag crypto-js itself (the compromised lookalike is a different package)', () => {
    // IMPORTANT: crypto-js is the legitimate, widely used library. It is NOT compromised.
    // Only a typosquat/lookalike of it was. Firing on crypto-js would be a serious FP.
    expectClean([pkg(base({ dependencies: { 'crypto-js': '4.2.0' } }))]);
  });

  it('does not flag superstring names built around a flagged name', () => {
    expectClean([
      pkg(
        base({
          dependencies: {
            'my-axios-wrapper': '1.14.1',
            axios2: '1.14.1',
            'intercom-client-mock': '7.0.4',
          },
        })
      ),
    ]);
  });

  it('does not flag substring names carved out of a flagged name', () => {
    expectClean([
      pkg(
        base({
          dependencies: {
            xios: '1.14.1',
            intercom: '7.0.4',
            tanstack: '1.169.5',
          },
        })
      ),
    ]);
  });

  it('does not flag case-variant lookalikes (npm names are lowercase; these are distinct strings)', () => {
    expectClean([pkg(base({ dependencies: { 'aXios-shim': '1.14.1' } }))]);
  });
});

// ---------- 13. overrides / resolutions pinning AWAY from the bad version ----------

describe('precision: overrides and resolutions that pin to safe versions', () => {
  it('does not flag npm overrides pinning axios to a safe version', () => {
    expectClean([
      pkg(
        base({
          dependencies: { 'some-sdk': '^3.0.0' },
          overrides: { axios: '1.15.0' },
        })
      ),
    ]);
  });

  it('does not flag yarn resolutions pinning flagged names to safe versions', () => {
    expectClean([
      pkg(
        base({
          dependencies: { 'some-sdk': '^3.0.0' },
          resolutions: { axios: '1.15.1', '@tanstack/react-router': '1.100.0' },
        })
      ),
    ]);
  });

  it('does not flag nested override paths that mention a flagged name safely', () => {
    expectClean([
      pkg(
        base({
          dependencies: { 'some-sdk': '^3.0.0' },
          overrides: { 'some-sdk': { axios: '1.14.2' } },
        })
      ),
    ]);
  });
});

// ---------- 14. scoped yarn entries with @ in name and version position ----------

describe('precision: scoped yarn.lock entries with @ in both positions', () => {
  it('does not flag a scoped yarn v1 entry resolving to a safe version', () => {
    expectClean([
      f(
        'yarn.lock',
        [
          '# yarn lockfile v1',
          '',
          '"@tanstack/react-router@^1.100.0":',
          '  version "1.100.0"',
          '  resolved "https://registry.yarnpkg.com/@tanstack/react-router/-/react-router-1.100.0.tgz#abc"',
          '',
        ].join('\n')
      ),
    ]);
  });

  it('does not flag a scoped non-flagged package whose spec equals a bad version number', () => {
    // @myco/axios is not axios. The @1.14.1 after the scope must bind to the wrong package.
    expectClean([
      f(
        'yarn.lock',
        [
          '# yarn lockfile v1',
          '',
          '"@myco/axios@1.14.1":',
          '  version "1.14.1"',
          '  resolved "https://registry.example.com/@myco/axios/-/axios-1.14.1.tgz#abc"',
          '',
        ].join('\n')
      ),
    ]);
  });

  it('does not flag scoped yarn berry entries with npm: protocol and safe versions', () => {
    expectClean([
      f(
        'yarn.lock',
        [
          '__metadata:',
          '  version: 8',
          '',
          '"@bitwarden/sdk-internal@npm:^0.2.0":',
          '  version: 0.2.3',
          '  resolution: "@bitwarden/sdk-internal@npm:0.2.3"',
          '',
          '"@tanstack/react-query@npm:^5.0.0":',
          '  version: 5.62.0',
          '  resolution: "@tanstack/react-query@npm:5.62.0"',
          '',
        ].join('\n')
      ),
    ]);
  });
});

// ---------- 15. empty version strings on packages with no known-bad versions ----------

describe('precision: empty or blank version specs on unflagged packages', () => {
  it('does not flag an empty-string spec on a package with no known-bad versions', () => {
    expectClean([pkg(base({ dependencies: { lodash: '' } }))]);
  });

  it('does not flag whitespace-only specs on unflagged packages', () => {
    expectClean([pkg(base({ dependencies: { react: ' ', 'left-pad': '\t' } }))]);
  });

  it('does not flag a lockfile entry with an empty version on an unflagged package', () => {
    expectClean([
      f(
        'package-lock.json',
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': { name: 'benign-app' },
            'node_modules/lodash': { version: '' },
          },
        })
      ),
    ]);
  });
});

// ---------- bonus hard negatives ----------

describe('precision: assorted hard negatives', () => {
  it('does not flag an empty file list', () => {
    expectClean([]);
  });

  it('does not flag a project with no manifest or lockfile at all', () => {
    expectClean([
      f('src/index.js', "console.log('hello');\n"),
      f('README.md', '# Benign app\n\nUses axios 1.15.1.\n'),
    ]);
  });

  it('does not flag a manifest with empty dependency blocks', () => {
    expectClean([pkg(base({ dependencies: {}, devDependencies: {}, optionalDependencies: {} }))]);
  });

  it('does not flag prerelease and build-metadata variants adjacent to the bad version', () => {
    // 1.14.1-beta.1 and 1.14.1+build.7 are distinct semver identities from 1.14.1... mostly.
    // Prerelease sorts BEFORE the release, so 1.14.1-beta.1 is not the compromised artifact.
    expectClean([pkg(base({ dependencies: { axios: '1.14.1-beta.1' } }))]);
  });

  it('does not flag npm alias specs that point at a safe version', () => {
    // "npm:axios@1.15.1" aliased under another name still resolves to safe axios.
    expectClean([pkg(base({ dependencies: { 'http-client': 'npm:axios@1.15.1' } }))]);
  });

  it('does not flag a package.json in a nested workspace folder with safe deps', () => {
    expectClean([
      pkg(base({ workspaces: ['packages/*'] })),
      pkg(
        { name: '@app/web', version: '0.1.0', dependencies: { axios: '^1.15.0' } },
        'packages/web/package.json'
      ),
    ]);
  });

  it('does not flag dist-tag-free exact pins on unflagged popular packages', () => {
    expectClean([
      pkg(
        base({
          dependencies: { react: '18.3.1', 'react-dom': '18.3.1', 'react-router-dom': '6.30.3' },
        })
      ),
    ]);
  });
});

// ---------- edge cases where benign-vs-compromised is genuinely ambiguous ----------
//
// These MAY fail against the current probe. Each one sits on a real judgment line:
// the statically-declared range brushes the compromised version, but the actually
// installed / pinned resolution is safe. Whether to fire is a policy call, not a bug
// either way. Kept in their own block so adjudication can weigh them separately.

describe('edge cases where benign-vs-compromised is genuinely ambiguous', () => {
  it('range intersects the bad version but the lockfile resolves safe', () => {
    // AMBIGUOUS: "^1.14.0" admits 1.14.1, but package-lock pins 1.14.2. The installed
    // tree is clean; the range is a footgun. Firing here is defensible advice but is a
    // false positive against the actual install state.
    expectClean([
      pkg(base({ dependencies: { axios: '^1.14.0' } })),
      f(
        'package-lock.json',
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': { name: 'benign-app', dependencies: { axios: '^1.14.0' } },
            'node_modules/axios': { version: '1.14.2' },
          },
        })
      ),
    ]);
  });

  it('wildcard "*" spec with a safe lockfile pin', () => {
    // AMBIGUOUS: "*" intersects every bad version of everything. With a lockfile pinning
    // 1.15.1 the install is safe. Flagging every wildcard would drown users in noise.
    expectClean([
      pkg(base({ dependencies: { axios: '*' } })),
      f(
        'package-lock.json',
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': { name: 'benign-app', dependencies: { axios: '*' } },
            'node_modules/axios': { version: '1.15.1' },
          },
        })
      ),
    ]);
  });

  it('yarn.lock descriptor mentions the bad version but resolution is safe', () => {
    // AMBIGUOUS: the entry KEY is "axios@^1.14.1" (a transitive dep asked for it),
    // but yarn resolved the range to 1.15.2. Matching on descriptor keys instead of the
    // "version" field would over-fire here; matching on version only under-reports the
    // requested range. The resolved artifact is the ground truth for what actually runs.
    expectClean([
      f(
        'yarn.lock',
        [
          '# yarn lockfile v1',
          '',
          'axios@^1.14.1:',
          '  version "1.15.2"',
          '  resolved "https://registry.yarnpkg.com/axios/-/axios-1.15.2.tgz#abc"',
          '',
        ].join('\n')
      ),
    ]);
  });

  // ADJUDICATED round 1: kept firing. Without a lockfile in the scan set,
  // "latest" on a package with a known-bad release is a real advisory (high,
  // not critical). With a lockfile pinning safe it is suppressed.
  it.skip('"latest" dist-tag on a flagged package name', () => {
    // AMBIGUOUS: "latest" is not statically resolvable. Today it points at a safe
    // release (the compromised versions were unpublished), but a scanner cannot prove
    // that offline. Zero-findings treats unresolvable tags as non-evidence; firing
    // treats them as unbounded ranges. Both positions are coherent.
    expectClean([pkg(base({ dependencies: { axios: 'latest' } }))]);
  });
});
