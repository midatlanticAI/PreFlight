// src/lib/probes/_internal/credential-shape.js
//
// Shared discipline for the question every secrets-shaped probe asks twice:
// does this NAME mean a credential, and does this VALUE look like one?
//
// Before 2026-09-03 the answers lived in fourteen adapter regexes and three
// v0.4 probes, in three drifting styles: exact match, ends-with, and
// substring-both-sides. The substring style is why TOKENIZER, cacheKey,
// translationKey, keyboard_map, $apiUrl and 'author' all fired as
// credentials. Every rule in this file was forced by a finding verified
// live against the probe stack on 2026-09-03; the FP corpus is pinned in
// src/test/secrets-precision-2026-09.test.js.

// Split an identifier into semantic segments: camelCase humps, snake_case and
// kebab-case parts, digit boundaries. 'translationKey' -> ['translation','key'],
// 'TOKEN_URL' -> ['token','url'], 'TOKENIZER' -> ['tokenizer'] (NOT 'token' —
// segment identity is the whole point), 'monkey' -> ['monkey'].
export function splitIdentifierSegments(name) {
  // Letter↔digit boundaries split too — Gate-3: without them, PASSWORD2
  // segmented as ['password2'], failed the vocabulary lookup, and every
  // consumer silently dropped digit-suffixed credential names
  // (ADMIN_PASSWORD2, API_KEY2 — the second database, the second key).
  return String(name)
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .replace(/([A-Za-z])(\d)/g, '$1 $2')
    .replace(/(\d)([A-Za-z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+| /)
    .filter(Boolean)
    .map((s) => s.toLowerCase());
}

// Segments that ARE the credential vocabulary.
const CREDENTIAL_SEGMENTS = new Set([
  'password',
  'passwd',
  'pwd',
  'secret',
  'token',
  'key',
  'apikey',
  'credential',
  'credentials',
]);

// A segment AFTER the credential word that says "this is metadata about the
// credential, not the credential": TOKEN_URL is where tokens come from,
// password_field is a form control, password_reset_message is copy.
const METADATA_QUALIFIERS = new Set([
  'url',
  'uri',
  'endpoint',
  'path',
  'route',
  'name',
  'label',
  'field',
  'input',
  'id',
  'type',
  'length',
  'len',
  'count',
  'index',
  'prefix',
  'suffix',
  // Gate-1 2026-09-03: API_KEY_HEADER / API_KEY_ENV name the header and the
  // env var that CARRY the key — the canonical read-from-environment idiom.
  'header',
  'headers',
  'env',
  'envvar',
  'var',
  // Canary round 2026-09-03: telemetry metric names and storage-entry ids
  // (TOKEN_USAGE, EVENT_API_KEY_UPDATED, DEFAULT_API_KEY_ENTRY,
  // TOKEN_EFFICIENCY, TOKEN_STORAGE_TYPE_COUNT) fired critical on waylou —
  // each trailing segment says "about the credential", not the credential.
  'entry',
  'entries',
  'updated',
  'update',
  'created',
  'deleted',
  'changed',
  'event',
  'events',
  'usage',
  'storage',
  'efficiency',
  'metric',
  'metrics',
  // Gate-1: hangman's secret_word and a quiz's secret_answer are game state,
  // not credentials — the two most-built beginner apps in this audience.
  'word',
  'number',
  'answer',
  'file',
  'dir',
  'hint',
  'error',
  'message',
  'msg',
  'title',
  'text',
  'placeholder',
  'pattern',
  'regex',
  'format',
  'mask',
  'policy',
  'rules',
  'requirements',
  'strength',
  'validator',
  'validation',
  'reset',
  'change',
  'form',
  'page',
  'view',
  'screen',
  'modal',
  'dialog',
  'icon',
  'button',
  'btn',
  'toggle',
  'visible',
  'visibility',
  'shown',
  'hidden',
]);

// True when the identifier, read as segments, names a credential. 'key' as a
// segment is deliberately weak on its own — cacheKey, routeKey, queryKey and
// translationKey are legitimate names for non-secrets — so a bare trailing
// 'key' still returns true here and the VALUE check below is the second gate
// that separates `apiKey = "sk-…"` from `cacheKey = "user:profile:v2"`.
export function nameIsCredentialish(name) {
  const segs = splitIdentifierSegments(name);
  // Every credential segment gets its own verdict, and one unqualified
  // credential segment anywhere makes the name credential-ish. Gate-1
  // 2026-09-03: an early return on the FIRST qualified segment made the
  // verdict order-dependent — PASSWORD_RESET_SECRET (password→reset
  // qualified, trailing SECRET never examined) was suppressed while the
  // segment-identical RESET_PASSWORD_SECRET fired. The trailing SECRET is a
  // real Flask/itsdangerous signing secret; password_reset_message stays
  // suppressed because 'message' qualifies its only credential segment.
  for (let i = 0; i < segs.length; i++) {
    if (!CREDENTIAL_SEGMENTS.has(segs[i])) continue;
    const next = segs[i + 1];
    if (next && METADATA_QUALIFIERS.has(next)) continue;
    return true;
  }
  return false;
}

// STRONG credential segments assert the value IS a credential all by
// themselves: SECRET_KEY, JWT_SECRET, BOT_TOKEN, astra_token, api_key. Bare
// 'key' is deliberately absent — cacheKey/routeKey/translationKey are why
// the identifier-shape value rejections exist at all. Gate-2 2026-09-03:
// applying those rejections to strong names silenced Django SECRET_KEY
// word-chains, Telegram bot tokens (colon format), and Astra/Ably keys.
const STRONG_CREDENTIAL_SEGMENTS = new Set([
  'password',
  'passwd',
  'pwd',
  'secret',
  'token',
  'apikey',
  'credential',
  'credentials',
]);

export function nameAssertsCredential(name) {
  const segs = splitIdentifierSegments(name);
  for (let i = 0; i < segs.length; i++) {
    const merged = segs[i + 1] ? segs[i] + segs[i + 1] : null;
    let hitLen = 0;
    if (STRONG_CREDENTIAL_SEGMENTS.has(segs[i])) hitLen = 1;
    else if (merged && STRONG_CREDENTIAL_SEGMENTS.has(merged)) hitLen = 2;
    if (hitLen === 0) continue;
    const after = segs[i + hitLen];
    if (after && METADATA_QUALIFIERS.has(after)) continue;
    return true;
  }
  return false;
}

// The closed vocabulary of validation-schema keywords. `password: 'required'`
// is the VeeValidate/Laravel string schema straight from the docs, and
// 'required' is never anyone's password — this tiny set is rejected even in
// password-named mode. Gate-1 2026-09-03.
const VALIDATION_KEYWORDS = new Set([
  'required',
  'optional',
  'nullable',
  'email',
  'string',
  'numeric',
  'boolean',
  'integer',
  'confirmed',
  'filled',
  'present',
  'accepted',
  'alpha',
  'alphanumeric',
  'date',
  'uuid',
  'array',
  'object',
]);

// Word-chain identifier: 2+ segments split on separators AND camel humps,
// every segment a plain word or a short version/number token. Catches
// 'onboarding_tutorial_v2', 'weather-forecast-v2-hourly' and
// 'hasCompletedOnboardingV2' — SharedPreferences keys, cache keys,
// UserDefaults keys (Gate-1 2026-09-03). Real key material has digit runs
// INSIDE segments, which fails the per-segment word test.
function looksLikeWordChainId(v) {
  const segs = String(v)
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+| /)
    .filter(Boolean);
  if (segs.length < 2) return false;
  // A "word" segment is a readable word — 12 chars caps it. A 15-char
  // all-caps run (sk_live_FAKEKEYFORTESTO) is key material whose separators
  // happen to split it, and treating it as a word chain broke the pinned
  // define('API_KEY', …) detection.
  return segs.every((s) => /^[A-Za-z]{1,12}$/.test(s) || /^v?\d{1,3}$/i.test(s));
}

// True when a quoted literal bound to a credential-ish name is shaped like an
// actual secret rather than like the identifiers that share the vocabulary.
// Each rejection cites the live-verified FP that forced it.
//
// opts.passwordNamed: the binding's name says password/passwd/pwd — the name
// already asserts the value IS a credential, so the identifier-shape
// rejections (word chains, dotted ids) are skipped: a diceware passphrase
// ('correct-horse-battery-staple') is exactly a word chain, and losing it
// was a Gate-1 confirmed recall bug. Prose, URLs, UI copy and validation
// keywords stay rejected in both modes.
export function valueLooksLikeSecret(value, opts = {}) {
  const v = String(value);
  const passwordNamed = opts.passwordNamed === true;
  // Google app passwords are displayed — and pasted — as four groups of four
  // lowercase letters, and Google ignores the spaces on auth. The shape is
  // exact; it beats the prose rejection below (Gate-2 confirmed recall bug:
  // SMTP_PASSWORD = "kdym vxwq zbtr fslg" was read as prose).
  if (/^(?:[a-z]{4} ){3}[a-z]{4}$/.test(v)) return true;
  // Prose: 'Enter your password', 'Check your email for the link'.
  if (/\s/.test(v)) return false;
  // URLs are config, not secrets: TOKEN_URL = "https://oauth2.googleapis.com/token",
  // $apiUrl = "https://api.stripe.com/v1/charges", #define API_BASE_URL.
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return false;
  // A version or a version range is a dependency pin, not a credential:
  // `"parse-passwd": "^1.0.0"` is a lockfile entry for a package whose name
  // happens to contain passwd, and it drew a critical on a canary corpus
  // (2026-10-28). Rejected in every mode; a password spelled 1.2.3 is the
  // documented cost.
  if (/^[\^~<>=]*v?\d+(?:\.\d+){1,2}(?:[-+][\w.]+)?$/.test(v)) return false;
  // Validation-schema keywords, closed set, rejected in every mode.
  if (VALIDATION_KEYWORDS.has(v.toLowerCase())) return false;
  // Title-case single words are UI copy — in any language. The ASCII-only
  // version of this rule suppressed 'Password' and 'Passwort' but fired
  // critical on 'Contraseña' and 'Şifre' (Gate-1: precision must not vary
  // by the user's natural language).
  if (/^\p{Lu}\p{Ll}+$/u.test(v)) return false;
  // (Title-case is rejected even for password-named keys: `password:
  // 'Contraseña'` — an inline label map — is far more common in this
  // audience's source than a committed Title-case dictionary-word password.
  // 'Sunshine' as an actual password is the documented cost, adjudicated
  // Gate-2 2026-09-03 against the Gate-1 label corpus.)
  // Laravel-style validation rule chains: 'required|min:8|confirmed'.
  // Rejected in every mode — like the keyword set, a rule chain is never a
  // password even under a password-named key.
  if (/^[a-z_]+(?::[\w,.]+)?(?:\|[a-z_]+(?::[\w,.]+)?)+$/i.test(v)) return false;
  // A strong credential NAME (passed by callers via passwordNamed, computed
  // with nameAssertsCredential) skips the identifier-shape rejections below:
  // those exist to disambiguate weak bare-'key' names (cacheKey, routeKey),
  // and applying them to SECRET_KEY / JWT_SECRET / BOT_TOKEN silenced real
  // word-chain secrets, Telegram's colon-format tokens, and Astra/Ably keys
  // (Gate-2 confirmed, 2026-09-03).
  // An UPPER_SNAKE identifier in the value position names the setting that
  // holds the credential, it is not the credential: `secret: 'ANTHROPIC_API_KEY'`
  // is a provider table saying which env var to read, and it drew four
  // criticals on one lookup table (field scan 2026-10-28). Rejected in every
  // mode. Two or more all-caps segments: a real password spelled
  // MY_SECRET_PASSWORD is the documented cost, and a single word ('HUNTER2')
  // still passes.
  if (/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(v)) return false;
  // A separator-joined word chain that carries a fixture marker as one of
  // its segments ('qa-auth-isolated-secret', 'test_session_secret',
  // 'dummy-token-value') is a harness value, in every mode: the marker is
  // the author saying so. The marker has to be a whole segment, so
  // 'contest-winner-2026' and 'devilish$' are untouched, and a chain with no
  // marker ('correct-horse-battery-staple') is still a passphrase.
  if (
    /^[A-Za-z0-9]+(?:[-_][A-Za-z0-9]+)+$/.test(v) &&
    /(?:^|[-_])(?:test|qa|dummy|fake|sample|example|placeholder|mock|stub|fixture)(?:[-_]|$)/i.test(
      v
    )
  )
    return false;
  if (passwordNamed) return true;
  // Namespaced ids: cacheKey := "user:profile:v2:default!". No real key
  // format uses colons; base64 never contains one.
  if (v.includes(':')) return false;
  // Route/path shapes: routeKeyHome = 'home/dashboard/main/v2'. Only when every
  // slash-separated segment reads as a short word — base64 with '/' (an AWS
  // secret) has long mixed-case segments and stays a secret.
  if (v.includes('/')) {
    const segs = v.split('/');
    const wordy = segs.every((s) => /^[a-z0-9_.-]{1,12}$/.test(s));
    if (wordy && segs.length >= 2) return false;
  }
  // Dotted identifier chains: 'auth.error.invalid.credentials',
  // 'transform.rotation.z.currentAnimation'. A JWT is also dotted but has
  // exactly two dots with long segments; identifier chains have short ones.
  const dotSegs = v.split('.');
  if (dotSegs.length >= 3 && dotSegs.every((s) => /^[A-Za-z][A-Za-z0-9_-]{0,23}$/.test(s))) {
    const looksJwt = dotSegs.length === 3 && dotSegs.every((s) => s.length >= 16);
    if (!looksJwt) return false;
  }
  // Word-chain identifiers across separator styles (see helper above).
  if (looksLikeWordChainId(v)) return false;
  // Laravel-style validation rule chains: 'required|min:8|confirmed'.
  if (/^[a-z_]+(?::[\w,.]+)?(?:\|[a-z_]+(?::[\w,.]+)?)+$/i.test(v)) return false;
  return true;
}

// Storage-key variant used by the client-auth-storage check. Same segment
// discipline, different vocabulary: 'author' must not read as auth, and a
// trailing bookkeeping qualifier ('tokenCount' — an LLM usage counter in this
// audience's apps, 'sessionTheme') marks the key as about-the-thing, not the
// thing.
const STORAGE_AUTH_SEGMENTS = new Set([
  'token',
  'jwt',
  'auth',
  'session',
  'bearer',
  'apikey',
  'accesstoken',
  'refreshtoken',
  'credential',
  'credentials',
]);
const STORAGE_BENIGN_QUALIFIERS = new Set([
  'count',
  'counts',
  'usage',
  'total',
  'limit',
  'cost',
  'price',
  'stat',
  'stats',
  'theme',
  'color',
  'pref',
  'prefs',
  'preference',
  'preferences',
  'ui',
  'tab',
  'view',
  'scroll',
  'filter',
  'sort',
  'order',
  'layout',
  'width',
  'height',
  'size',
  'position',
  // 'state' is deliberately NOT benign: 'authState' is the standard
  // redux-persist / context slice that HOLDS the token (Gate-1 confirmed
  // recall bug). OAuth's public `state` param is separately exempted by
  // OAUTH_PUBLIC_RE at the call site.
  'history',
  'draft',
  'name',
  'label',
  // 'id' is deliberately NOT here: sessionId / tokenId IS the credential,
  // not bookkeeping about it — caught by the existing adversarial suite.
  'timeout',
  'expiry',
  'expiration',
  'ttl',
  'duration',
]);

// Adjudicate an ASSIGN_LITERAL_RE match from a v0.5 language adapter. The
// fourteen adapters find candidate lines with per-language regexes; this is
// the single shared answer to "was that actually a credential assignment?".
// It parses the matched snippet generically — the last quoted literal is the
// value, and the name is the last identifier-ish token before it that
// carries credential vocabulary — so per-language capture groups are not
// needed. FP triage 2026-09-03: cacheKey/translationKey/routeKey/queryKey
// ids, $apiUrl/API_BASE_URL/TOKEN_URL endpoints, and keyboard_map all fired
// as critical hardcoded secrets across Go, Kotlin, Dart, PHP, Ruby, Swift,
// Scala, Rust, C and C++.
const FIND_VOCAB_RE = /key|secret|token|password|passwd|pwd|api|credential/i;

export function credentialAssignmentIsReal(snippet) {
  const s = String(snippet);
  const valueMatch = s.match(/(['"])((?:(?!\1).)*)\1(?:\s*\))?\s*$/);
  if (!valueMatch) return true; // unrecognized shape — defer to the regex that matched
  const value = valueMatch[2];
  const preValue = s.slice(0, valueMatch.index);
  const tokens = preValue.match(/[A-Za-z_][A-Za-z0-9_]*/g) || [];
  let name = null;
  for (let i = tokens.length - 1; i >= 0; i--) {
    if (FIND_VOCAB_RE.test(tokens[i])) {
      name = tokens[i];
      break;
    }
  }
  if (name === null) return true; // defer — the adapter regex saw something segment parsing cannot
  return (
    nameIsCredentialish(name) &&
    valueLooksLikeSecret(value, { passwordNamed: nameAssertsCredential(name) })
  );
}

export function storageKeyIsAuthish(key) {
  const segs = splitIdentifierSegments(key);
  for (let i = 0; i < segs.length; i++) {
    const merged2 = segs[i] + (segs[i + 1] || '');
    const hit =
      STORAGE_AUTH_SEGMENTS.has(segs[i]) || STORAGE_AUTH_SEGMENTS.has(merged2.toLowerCase());
    if (!hit) continue;
    const after = STORAGE_AUTH_SEGMENTS.has(segs[i]) ? segs[i + 1] : segs[i + 2];
    // continue, not return — Gate-3 found the same order-dependence this
    // file's own nameIsCredentialish comment documents: sessionStatsToken
    // ('session'+'stats' short-circuited, trailing 'token' never examined)
    // was clean while segment-identical statsSessionToken fired.
    if (after && STORAGE_BENIGN_QUALIFIERS.has(after)) continue;
    return true;
  }
  return false;
}
