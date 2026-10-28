// src/lib/probes/v05/adapters/cpp/cpp-deserialize-001-binary-archive.js
//
// XL-001 adapter for C++. RX-based, two signals in the same file. The
// inventory planned "custom binary parsers" for C++, but a hand-rolled
// parser has no fixed token an RX can bind, so this adapter detects the
// named object-graph archive libraries instead: a cereal
// BinaryInputArchive / PortableBinaryInputArchive or a
// boost::archive::binary_iarchive constructed in a file that also reads
// from the network (recv / recvfrom / recvmsg, asio read_some /
// async_read, or a request body). Both archives reconstruct typed object
// graphs from raw bytes with no allowlist, which is the CWE-502 shape.
//
// The two-signal requirement is the FP gate that matters: the same
// archive over the app's own cache file on disk is the library's intended
// use and stays silent. Comment handling carries block-comment state
// across lines (forEachCFamilyCodeLine), and preprocessor lines are
// skipped so #include <boost/archive/binary_iarchive.hpp> is not read as
// a construction.

import { cppFiles } from '../../shared-detectors/c-family-scope.js';
import { forEachCFamilyCodeLine } from '../../shared-detectors/c-family-auth.js';

const PROBE_NAME = 'C++ Unsafe Deserialization';

// Binary input-archive class names. The output archives (BinaryOutputArchive,
// binary_oarchive) are different tokens and never match.
const ARCHIVE_RE =
  /\b(?:cereal\s*::\s*)?(?:PortableBinaryInputArchive|BinaryInputArchive)\b|\b(?:boost\s*::\s*archive\s*::\s*)?binary_iarchive\b/;

// A network / attacker-controlled byte source somewhere in the same file.
const NETWORK_RE =
  /\brecv(?:from|msg)?\s*\(|\bread_some\s*\(|\basync_read(?:_some)?\s*\(|\basio\s*::\s*(?:read|async_read)\b|\breq(?:uest)?\s*(?:\.|->)\s*body\b/;

export const CPP_DESERIALIZE_001 = {
  probe_id: 'CPP-DESERIALIZE-001',
  xl_family: 'XL-001',
  language: 'cpp',
  name: PROBE_NAME,
  category: 'security',
  severity: 'critical',
  confidence: 'medium',
  cwe: 'CWE-502',
  owasp_web: 'A08',
  owasp_llm: null,
  detector: 'rx',
  scope: '**/*.{cpp,cc,cxx,hpp,hh,hxx}',
  what_it_catches:
    'A cereal BinaryInputArchive / PortableBinaryInputArchive or boost::archive::binary_iarchive constructed in a file that also reads bytes from the network (recv, asio read_some / async_read, a request body). Both archives rebuild typed object graphs from raw bytes with no type allowlist.',
  why_ai_v05:
    'cereal and boost::serialization are the corpus answer to "send this struct over the socket," so the assistant wires the archive straight to the received buffer. The libraries themselves document that they are not hardened against adversarial input.',
  vibe_v05:
    '"Serialize the struct, stream it across, deserialize on the other side." The archive header and object graph are trusted as if this process wrote them.',
  detection_approach:
    'Two RX signals in the same file: a binary input-archive construction plus a network read (recv family, asio reads, request body). Walked with block-comment state carried across lines; preprocessor lines skipped.',
  fp_gates_v05: [
    'line and block comments, tracked with state carried across lines (forEachCFamilyCodeLine)',
    'archives over a local trusted file with no network read anywhere in the file — the second signal is required',
    'output archives (BinaryOutputArchive / binary_oarchive) — different tokens, never matched',
    'preprocessor lines, so #include of the archive headers is not read as a construction',
    '_test/_unittest/_spec file names, vendored trees, scanner self-source, and the fixture tree (cppFiles())',
  ],
  remediation:
    'Do not feed network bytes to a general object-graph archive. Parse the wire format with a schema-checked codec (protobuf, flatbuffers with verifier, or a hand-validated fixed layout), enforce length limits before parsing, and keep cereal / boost archives for artifacts this process wrote itself.',
  autofix_v05: 'manual',
  fixtures_v05: {
    positive: 'src/lib/probes/v05/fixtures/CPP-DESERIALIZE-001/positive.cpp',
    negative: 'src/lib/probes/v05/fixtures/CPP-DESERIALIZE-001/negative.cpp',
  },
  known_incidents:
    'CWE-502; OWASP A08; both cereal and boost::serialization document that untrusted archive input is out of their threat model',
  ioc_bundle_ref: null,
  maturity: 'experimental',
  shadow: false,
  legacy_finding_id_seed: null,
  detect(files) {
    const findings = [];
    for (const f of cppFiles(files)) {
      const archiveLines = [];
      let networkSource = false;
      forEachCFamilyCodeLine(f.content, (line, i) => {
        if (/^\s*#/.test(line)) return; // preprocessor
        if (!networkSource && NETWORK_RE.test(line)) networkSource = true;
        if (ARCHIVE_RE.test(line)) archiveLines.push({ line, i });
      });
      if (!networkSource) continue;
      for (const { line, i } of archiveLines) {
        findings.push({
          id: `cpp-deser-${f.path}-${i}`,
          probe: PROBE_NAME,
          title: 'Unsafe deserialization: binary object archive over network-read bytes',
          severity: 'critical',
          category: 'Security',
          cwe: 'CWE-502',
          file: f.path,
          line: i + 1,
          evidence: line.trim().slice(0, 200),
          remediation:
            'Parse network bytes with a schema-checked codec and length limits. Keep cereal / boost binary archives for artifacts this process wrote itself.',
        });
      }
    }
    return findings;
  },
};
