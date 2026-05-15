// src/lib/probes/v05/families/index.js
//
// XL-001 through XL-012 family records aggregated for the manifest.

import { XL_001 } from './xl-001-unsafe-deserialization.js';
import { XL_002 } from './xl-002-raw-query-interpolation.js';
import { XL_004 } from './xl-004-tls-verification-disabled.js';
import { XL_006 } from './xl-006-hardcoded-secrets.js';

/** @type {object[]} */
export const FAMILIES = [XL_001, XL_002, XL_004, XL_006];
