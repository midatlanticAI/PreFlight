// src/lib/probes/v05/adapters/index.js
//
// Language-specific adapter records aggregated for the manifest.

import { PY_DESERIALIZE_001 } from './python/py-deserialize-001-unsafe-load.js';
import { PY_SQL_RAW_001 } from './python/py-sql-raw-001-interpolation.js';
import { PY_TLS_VERIFY_001 } from './python/py-tls-verify-001-disabled.js';
import { PY_SECRETS_001 } from './python/py-secrets-001-hardcoded-key.js';

/** @type {object[]} */
export const ADAPTERS = [PY_DESERIALIZE_001, PY_SQL_RAW_001, PY_TLS_VERIFY_001, PY_SECRETS_001];
