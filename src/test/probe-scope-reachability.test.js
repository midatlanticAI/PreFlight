// Intake reachability: can a probe's files actually get through the front door?
//
// Every scan enters through shouldScanFile(). A probe whose file extension is
// missing from FILE_INCLUDE is rejected before the probe runs, so it fires on
// zero real scans no matter how correct it is. That is exactly what had
// happened: 33 probes across 9 languages (C, C++, C#, Rust, Kotlin, Swift,
// Scala, Elixir, Dart) shipped with passing fixtures and could not reach a
// single real file, while the FAQ named all of them.
//
// Fixture tests could not catch it because they hand the adapter a file
// directly and never cross the intake boundary. This test asserts the join
// between the manifest's declared scope and the filter, which is the seam
// where a probe silently stops existing.

import { describe, it, expect } from 'vitest';
import { shouldScanFile } from '../lib/file-filter.js';
import { PROBE_MANIFEST_V05, isLiveAdapter } from '../lib/probes/v05/manifest.js';

// A representative source path per extension the manifest declares.
const samplePathFor = (ext) => `src/sample_module.${ext}`;

// Pull the extensions out of an adapter's scope glob, e.g.
// '**/*.{js,jsx,ts}' -> ['js','jsx','ts']; '**/*.kt' -> ['kt'].
function extensionsFromScope(scope) {
  if (typeof scope !== 'string') return [];
  const braced = scope.match(/\{([^}]+)\}/);
  if (braced) return braced[1].split(',').map((s) => s.trim().replace(/^\./, ''));
  const single = scope.match(/\.([A-Za-z0-9]+)$/);
  return single ? [single[1]] : [];
}

const liveAdapters = Object.values(PROBE_MANIFEST_V05).filter(isLiveAdapter);

describe('probe intake reachability', () => {
  it('there are live adapters to check', () => {
    expect(liveAdapters.length).toBeGreaterThan(0);
  });

  it('every live adapter declares a scope with at least one parseable extension', () => {
    const unparseable = liveAdapters
      .filter((a) => extensionsFromScope(a.scope).length === 0)
      .map((a) => `${a.probe_id}: scope=${JSON.stringify(a.scope)}`);
    expect(unparseable).toEqual([]);
  });

  it('every live adapter can actually receive a file through shouldScanFile', () => {
    // The failure this pins: an adapter whose language the intake filter drops.
    const unreachable = [];
    for (const adapter of liveAdapters) {
      const exts = extensionsFromScope(adapter.scope);
      const reachable = exts.filter((ext) => shouldScanFile(samplePathFor(ext)));
      if (reachable.length === 0) {
        unreachable.push(`${adapter.probe_id} (${adapter.language}): none of .${exts.join(', .')}`);
      }
    }
    expect(unreachable).toEqual([]);
  });

  it('each individual extension a live adapter claims is admitted', () => {
    // Stricter than the test above: an adapter scoped to {c,h} whose .h files
    // are dropped is half-dead, and half-dead is the state that looks healthy.
    const dropped = [];
    for (const adapter of liveAdapters) {
      for (const ext of extensionsFromScope(adapter.scope)) {
        if (!shouldScanFile(samplePathFor(ext))) {
          dropped.push(`${adapter.probe_id}: .${ext}`);
        }
      }
    }
    expect(dropped).toEqual([]);
  });

  it('the languages the product advertises are all scannable', () => {
    // Pinned by name, because this list is a public claim on the home page and
    // in the FAQ. If a language is dropped from the product, delete it here on
    // purpose rather than letting the intake filter decide silently.
    const ADVERTISED = {
      Python: 'src/app.py',
      Go: 'src/main.go',
      Ruby: 'app/models/user.rb',
      PHP: 'src/index.php',
      Java: 'src/Main.java',
      Kotlin: 'src/Main.kt',
      Swift: 'Sources/Auth.swift',
      Scala: 'src/Main.scala',
      Elixir: 'lib/auth.ex',
      Dart: 'lib/main.dart',
      'C#': 'src/Auth.cs',
      Rust: 'src/main.rs',
      C: 'src/auth.c',
      'C++': 'src/auth.cpp',
      JavaScript: 'src/app.js',
      TypeScript: 'src/app.ts',
    };
    const dead = Object.entries(ADVERTISED)
      .filter(([, path]) => !shouldScanFile(path))
      .map(([lang, path]) => `${lang} (${path})`);
    expect(dead).toEqual([]);
  });

  it('widening intake did not admit vendored C / C++ / JVM trees', () => {
    // Admitting C-family extensions makes these directories reachable for the
    // first time, and a vendored library is not the author's code to fix.
    for (const path of [
      'third_party/jwt-cpp/include/jwt.h',
      '3rdparty/openssl/crypto/evp.c',
      'external/googletest/src/gtest.cc',
      'extern/fmt/src/format.cc',
      'deps/libuv/src/unix/core.c',
      'contrib/zlib/deflate.c',
      'subprojects/glib/glib/gmain.c',
      'submodules/asio/include/asio.hpp',
      'vendor/rails/activerecord.rb',
    ]) {
      expect(shouldScanFile(path), `${path} should be excluded as vendored`).toBe(false);
    }
  });

  it('first-party C-family source is still scanned', () => {
    // The exclusions above must not swallow the author's own code. "external"
    // as a path SEGMENT is vendored; as part of a filename it is not.
    for (const path of [
      'src/auth.c',
      'src/auth.h',
      'src/crypto/verify.cpp',
      'include/token.hpp',
      'lib/external_api_client.c',
      'src/deps_resolver.cs',
    ]) {
      expect(shouldScanFile(path), `${path} should be scanned`).toBe(true);
    }
  });
});
