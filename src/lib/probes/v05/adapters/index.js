// src/lib/probes/v05/adapters/index.js
//
// Language-specific adapter records aggregated for the manifest.
//   - python/*   : Phase 1 (XL-001/002/004/006), independent detection
//   - javascript/*: Phase 2 migration of overlapping v0.4 probes
//                    (Secret Scanner, SQL Injection, Auth Weakness) with
//                    legacy_finding_id_seed for stableId continuity

import { PY_DESERIALIZE_001 } from './python/py-deserialize-001-unsafe-load.js';
import { PY_SQL_RAW_001 } from './python/py-sql-raw-001-interpolation.js';
import { PY_TLS_VERIFY_001 } from './python/py-tls-verify-001-disabled.js';
import { PY_SECRETS_001 } from './python/py-secrets-001-hardcoded-key.js';
import { JS_SECRET_001 } from './javascript/js-secret-001-hardcoded.js';
import { JS_SQL_RAW_001 } from './javascript/js-sql-raw-001-template-literal.js';
import { JS_AUTH_001 } from './javascript/js-auth-001-token-verification.js';

/** @type {object[]} */
export const ADAPTERS = [
  PY_DESERIALIZE_001,
  PY_SQL_RAW_001,
  PY_TLS_VERIFY_001,
  PY_SECRETS_001,
  JS_SECRET_001,
  JS_SQL_RAW_001,
  JS_AUTH_001,
];
