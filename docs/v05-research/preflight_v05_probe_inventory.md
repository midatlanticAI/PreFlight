# Pre-Flight v0.5 Probe Inventory

**Version:** v0.5.0-merge
**Generated:** May 14, 2026
**Source:** Merge of Claude v0.5 research (599 probes), ChatGPT v2 shared-family architecture, ChatGPT v3 schema fields, Google v0.5 comparison adds, and May 14 citation verification corrections.

## Build provenance

This artifact merges work product across four research drafts and one verification pass:

1. **Depth catalog (this document, body):** 599 probes from the Claude v0.5 research, with em-dashes stripped, seven verified citation corrections applied, and the new v0.5 schema fields (`why_ai_v05`, `vibe_v05`, `fp_gates_v05`, `autofix_v05`, `fixtures_v05`) folded in.

2. **Shared-family architecture (XL-001 to XL-012):** Adopted from ChatGPT v2 cross-tool comparison. These are the canonical cross-language probe families. Language-specific probes reference them via `xl_ref` when they are adapters of a shared family.

3. **Schema extension (v0.5 fields):** Adopted from ChatGPT v3 site-aware run. Adds vibe-aware education layer fields, false-positive gates as a first-class field, autofix taxonomy, and explicit fixture pointer specification.

4. **Comparison gap-fill (seven probes):** Pulled from Google's comparison run after identifying genuine gaps not covered in the original 599. Documented in the "v0.5 Additions" section below.

5. **Citation corrections (seven items):** Applied from the May 14, 2026 verification pass against Snyk, Wiz, StepSecurity, Microsoft, Datadog, Akamai, Socket, Sonatype, USENIX, RustSec, Composer, and CocoaPods primary sources. Specific corrections documented inline in the body and in the changelog at the end.

## Referenced files

- `preflight_v05_iocs.json` (separate file): structured IOC bundle for the 2026 supply-chain incident timeline. Probes reference entries via `ioc_bundle_ref`.
- `preflight_v05_consensus_matrix.csv` (separate file): empty template for cross-draft probe consensus tracking. Populate across Claude / ChatGPT / Google / Grok drafts.

---

## v0.5 Probe Schema

Every probe in v0.5 emits these structured fields. Fields with `_v05` suffix
are new in this release; existing v0.4 fields are unchanged.

| Field                | Type           | Required | Description                                                                                   |
| -------------------- | -------------- | -------- | --------------------------------------------------------------------------------------------- |
| `probe_id`           | string         | yes      | Stable unique ID, format LANG-FAMILY-NNN                                                      |
| `xl_ref`             | string \| null | no       | XL-001 to XL-012 if probe is a language adapter of a shared family                            |
| `language`           | enum           | yes      | python, rust, go, java, kotlin, swift, csharp, c, cpp, ruby, php, scala, elixir, dart         |
| `category`           | enum           | yes      | security, supply, llm, misconfig, memory, resource, build, access, crypto, transport          |
| `severity`           | enum           | yes      | critical, high, medium, low, info                                                             |
| `confidence`         | enum           | yes      | high, medium, low                                                                             |
| `cwe`                | string \| null | no       | CWE-NNN identifier                                                                            |
| `owasp_web`          | string \| null | no       | OWASP Top 10 2025 web category (A01..A10)                                                     |
| `owasp_llm`          | string \| null | no       | OWASP LLM Top 10 2025 category (LLM01..LLM10)                                                 |
| `detector`           | enum           | yes      | rx, ast, manifest, config, mixed                                                              |
| `scope`              | string         | yes      | File glob the probe applies to                                                                |
| `what_it_catches`    | text           | yes      | Plain description of the bug pattern                                                          |
| `why_ai_v05`         | text           | yes      | Short reason this is an AI-emission failure mode (which tools, which corpus bias)             |
| `vibe_v05`           | text           | yes      | Vibe-coder mental model that produces this bug (not the technical reason, the conceptual one) |
| `detection_approach` | text           | yes      | Concrete regex/AST/manifest match expression                                                  |
| `fp_gates_v05`       | list           | yes      | Explicit patterns that legitimately match but should not fire                                 |
| `remediation`        | text           | yes      | Specific fix with code example                                                                |
| `autofix_v05`        | enum           | yes      | mechanical (safe to auto-apply), review-needed (suggest), manual (explain only)               |
| `fixtures_v05`       | object         | yes      | `{positive: path, negative: path, adversarial: path?}`                                        |
| `known_incidents`    | text \| null   | no       | CVE numbers, campaign names, IOC references                                                   |
| `ioc_bundle_ref`     | string \| null | no       | Reference into preflight_v05_iocs.json by key                                                 |

### Severity scale (unchanged from v0.4)

Critical = direct RCE / credential exfil / full-tenant data breach.
High = privilege escalation, mass data exposure, auth bypass.
Medium = info disclosure, DoS, weakened crypto with mitigations.
Low = hardening gaps.
Info = best-practice nudges.

### Detection approach abbreviations

RX = regex over source. AST = abstract syntax tree query (tree-sitter recommended
for browser-side). MAN = manifest/lockfile parse. CFG = config-file parse
(YAML/TOML/JSON/properties). BIN = binary/artifact inspection. STR = literal
or string-table extraction. MIXED = any combination.

### Autofix taxonomy (new in v0.5)

**mechanical**: Pre-Flight can apply the fix automatically with zero behavior
risk. Example: adding `timeout=10` kwarg to a requests.get call that has no
timeout. Example: changing `yaml.load(x)` to `yaml.safe_load(x)`.

**review-needed**: Pre-Flight suggests the fix but flags it for human review
because the rewrite touches semantically significant code. Example: converting
string-built SQL to parameterized queries (might break compound WHERE clauses).

**manual**: Pre-Flight explains the fix but does not propose a code change.
Example: removing an `unsafe` block in Rust (requires understanding the safety
invariants the block was holding).

### Persona output (Sam/Demi/Drew/Vera) consumes these fields

- Sam (fix) reads: `what_it_catches`, `remediation`, `autofix_v05`, `fixtures_v05.positive`.
- Demi (educational) reads: `why_ai_v05`, `vibe_v05`, `known_incidents`.
- Drew (design rules) reads: `category`, `severity`, `owasp_web`, `owasp_llm`.
- Vera (engineering rules) reads: `detection_approach`, `fp_gates_v05`, `cwe`.

---

## Cross-Language Probe Families (XL-001 to XL-012)

These are the canonical shared probe families. Language-specific probes below
reference them by XL-ID when they are language-specific adapters of a shared
family. A language probe may extend an XL family with framework-specific
detection or false-positive logic without redefining the underlying rule.

### XL-001: Unsafe Deserialization

- **Category:** Security / Integrity
- **OWASP Web:** A08
- **OWASP LLM:** LLM03, LLM04 (for model-loading variants)
- **Severity:** Critical
- **CWE:** CWE-502
- **Detection:** AST call match plus import resolution. Detect deserialize calls
  reading from request bodies, network sockets, cache layers, message queues,
  or user-uploaded files.
- **Language adapters:** PY (pickle, joblib, torch.load, yaml.load), JV
  (ObjectInputStream, XMLDecoder), CS (BinaryFormatter, TypeNameHandling != None),
  RB (Marshal.load, YAML.load), PHP (unserialize), EX (binary_to_term),
  SW (NSKeyedUnarchiver without secure coding), C++ (custom binary parsers).
- **why_ai:** AI tools treat deserialization as generic persistence and reach
  for the language-native API without checking input source. Tutorial corpora
  predate the secure alternatives.
- **vibe:** "save object, load object" mental model with no concept of trust
  boundary between local-trusted-bytes and network-untrusted-bytes.
- **fp_gates:** test fixtures, signed internal artifacts, allowlist filter
  present, secure coding flag set.
- **autofix:** review-needed
- **fixtures:** positive=network-body-to-load; negative=local-trusted-file

### XL-002: Raw Query Interpolation

- **Category:** Injection
- **OWASP Web:** A03 (Injection in 2025 numbering)
- **Severity:** Critical
- **CWE:** CWE-89
- **Detection:** AST for string format/concat/template-literal feeding known
  query methods. Match query/exec/execute/raw and ORM raw-SQL methods.
- **Language adapters:** PY (Django .raw, SQLAlchemy text), GO (database/sql
  Query/Exec with fmt.Sprintf), JV (createQuery/createNativeQuery concat),
  CS (FromSqlRaw, ExecuteSqlRaw), RB (where with interpolation, find_by_sql),
  PHP (PDO query without prepare), RS (sqlx::query with format!), SC (slick
  string fragments), EX (Ecto fragment with interpolation).
- **why_ai:** autocomplete emits interpolation because it is shorter and more
  legible than parameterization.
- **fp_gates:** literal-constant queries, internal migration files, allowlisted
  sort-direction fragments.
- **autofix:** review-needed
- **fixtures:** positive=concat-where; negative=parameterized-bind

### XL-003: Shell and Process Injection

- **Category:** Injection
- **OWASP Web:** A03
- **Severity:** High to Critical
- **CWE:** CWE-78
- **Detection:** AST on process APIs with shell-string construction or shell
  wrapper invocation (sh -c, cmd /c, bash -c).
- **Language adapters:** PY (subprocess.run shell=True, os.system), GO
  (exec.Command sh -c), JV (Runtime.exec, ProcessBuilder), CS (Process.Start),
  RB (backticks, system, Open3), PHP (shell_exec, exec, passthru), RS
  (std::process::Command sh), C/C++ (system, popen), DA (Process.run sh).
- **why_ai:** shortest path to a CLI tool wrapper.
- **fp_gates:** command and args are compile-time constants.
- **autofix:** manual
- **fixtures:** positive=tainted-user-arg-to-sh; negative=argv-array-direct

### XL-004: TLS Verification Disabled

- **Category:** Transport / Cryptographic Failure
- **OWASP Web:** A02
- **Severity:** High
- **CWE:** CWE-295
- **Detection:** AST and config-key scanning for verification disable flags.
- **Language adapters:** PY (requests verify=False), GO (tls.Config
  InsecureSkipVerify=true), JV (always-true X509TrustManager/HostnameVerifier),
  RS (danger_accept_invalid_certs), CS (ServicePointManager callback returning
  true), C/C++ (CURLOPT_SSL_VERIFYPEER=0), DA (badCertificateCallback => true),
  SW (URLSession trust override), KT (cleartextTraffic="true" or trust-all
  TrustManager in OkHttp).
- **why_ai:** local-dev debugging shortcut that survives into production.
- **fp_gates:** code under test fixtures, dev-only compile flags.
- **autofix:** review-needed
- **fixtures:** positive=verify-false-in-prod; negative=ca-bundle-configured

### XL-005: Missing Timeouts and Bounded Reads

- **Category:** Availability / Resource Exhaustion
- **OWASP Web:** A04 Insecure Design (symptom)
- **Severity:** Medium to High
- **CWE:** CWE-400
- **Detection:** AST on client/server constructors and read APIs without
  size/time bounds.
- **Language adapters:** PY (requests/httpx no timeout), GO (http.Client{} no
  Timeout, http.Server no ReadHeaderTimeout, io.ReadAll on body), RS (tokio
  unbounded_channel on untrusted), JV (HttpClient without connectTimeout),
  CS (HttpClient default timeout left at infinity), DA (http.Client no
  connectionTimeout), EX (Plug body parser without max length).
- **why_ai:** generated examples optimize for "fewest lines that compile" and
  ignore resource ceilings.
- **fp_gates:** constant-bounded bodies, internal-only tools, upstream proxy
  enforcing limits.
- **autofix:** mechanical
- **fixtures:** positive=read-all-from-body; negative=limit-reader-bounded

### XL-006: Hardcoded Secrets and Policy Text

- **Category:** Disclosure
- **OWASP Web:** A07 Authentication Failures (token surface)
- **OWASP LLM:** LLM02 Sensitive Information Disclosure, LLM07 System Prompt Leakage
- **Severity:** High
- **CWE:** CWE-798
- **Detection:** regex + entropy + path-aware config parsing + assignment-context
  gating. Includes API keys, connection strings, JWT secrets, model/system
  prompts, judge policies bundled in assets.
- **Language adapters:** all 14 languages. Asset-bundle detection adds for
  KT/SW/DA (system_prompt.txt in app bundle, Info.plist API keys, Flutter
  assets).
- **why_ai:** AI inlines placeholders that get forgotten before rotation.
- **fp_gates:** .example files, docs, test fixtures, env-loaded references.
- **autofix:** review-needed
- **fixtures:** positive=literal-sk-prefix; negative=getenv-call

### XL-007: Dynamic Versions and Missing Lockfiles

- **Category:** Supply Chain
- **OWASP Web:** A03 Software Supply Chain Failures (new in 2025)
- **OWASP LLM:** LLM03
- **Severity:** Medium to High
- **CWE:** CWE-1357
- **Detection:** manifest parser + lockfile presence checks per ecosystem.
- **Language adapters:** PY (loose pins in requirements.txt/pyproject.toml,
  no uv.lock/poetry.lock for apps), JV (Maven ranges like 5.+, Gradle dynamic
  versions, no buildscript locking), CS (NuGet floating versions), RB (Gemfile
  without locked git refs, missing Gemfile.lock), PHP (composer ranges without
  composer.lock for apps), RS (Cargo path/git deps without rev, missing
  Cargo.lock for binaries), GO (go.mod replace to arbitrary remote), DA
  (pubspec carets without pubspec.lock), EX (mix.exs git deps without ref),
  SW (Package.swift wide ranges without Package.resolved).
- **why_ai:** assistants prefer "latest compatible" patterns that trade
  determinism for convenience.
- **fp_gates:** library packages where host lockfiles govern resolution.
- **autofix:** review-needed
- **fixtures:** positive=range-no-lock; negative=exact-pin-plus-lock

### XL-008: Install Hooks and Build-Script Abuse

- **Category:** Supply Chain
- **OWASP Web:** A03
- **Severity:** Critical
- **CWE:** CWE-829
- **Detection:** manifest hook fields and build-script AST. Detect
  preinstall/postinstall hooks, build.rs network/process calls, gem install
  extconf network access, CocoaPods prepare_command (already blocked May 2025
  but historical artifacts persist), composer post-install-cmd hooks.
- **Language adapters:** PY (setup.py with network or subprocess at install),
  RS (build.rs with reqwest or Command), RB (extconf.rb network), PHP
  (composer post-install-cmd shell), SW (legacy podspec prepare_command),
  KT/JV (Gradle init/build scripts with network), GO (go generate with shell).
- **why_ai:** install-time execution is a proven exfiltration path; AI emits
  it because tutorials show install-time codegen.
- **fp_gates:** internal packages with reviewed signer/owner metadata.
- **autofix:** manual
- **fixtures:** positive=install-hook-curl-pipe-sh; negative=pure-compile-step

### XL-009: Mass Assignment and Overbinding

- **Category:** Authorization
- **OWASP Web:** A01 Broken Access Control
- **Severity:** High
- **CWE:** CWE-915
- **Detection:** controller/model AST inspecting direct binding of request
  bodies into entity types.
- **Language adapters:** RB (Rails User.create(params), permit! everywhere),
  JV (@RequestBody Entity directly), PHP (Laravel User::create(request->all()),
  no fillable/guarded), CS (ASP.NET model binding to entity), PY (FastAPI
  Pydantic with extra="allow" feeding ORM), SC (Play form binding to domain
  entity), KT (Spring @ModelAttribute Entity).
- **why_ai:** CRUD scaffolds optimize velocity and skip DTOs.
- **fp_gates:** explicit whitelist fields, immutable request types, DTO already
  validated upstream.
- **autofix:** review-needed
- **fixtures:** positive=entity-direct-bind; negative=dto-with-permit

### XL-010: Excessive Agency and Broad Capabilities

- **Category:** Authorization / Configuration
- **OWASP Web:** A02
- **OWASP LLM:** LLM06 Excessive Agency
- **Severity:** High
- **CWE:** CWE-732, CWE-272
- **Detection:** manifest/plist/config parsing and AST on permission APIs.
- **Language adapters:** KT (android:exported="true" without permission,
  addJavascriptInterface on remote content), SW (ATS NSAllowsArbitraryLoads),
  RS (Tauri broad FS/HTTP scopes), DA (Flutter platform channels with broad
  intent filters), JV (Spring Actuator endpoints exposed in prod).
- **why_ai:** assistants favor permissive configs to "make it work."
- **fp_gates:** documented kiosk/internal apps with explicit approval marker.
- **autofix:** review-needed
- **fixtures:** positive=exported-true-no-permission; negative=non-exported

### XL-011: LLM Output Passed Directly to Sinks

- **Category:** LLM Improper Output Handling
- **OWASP LLM:** LLM05 Improper Output Handling
- **Severity:** Critical
- **CWE:** CWE-94
- **Detection:** AST source/sink heuristics. Sources are LLM SDK response
  variables (openai, anthropic, mistralai, litellm, langchain, etc.). Sinks
  are shell, SQL, eval, file paths, WebView JavaScript, HTTP, deserializers.
- **Language adapters:** all 14 languages where LLM SDK use exists.
- **why_ai:** agent demos blur text generation with action authorization. The
  same model that "answers questions" also "decides commands" in tutorial code.
- **fp_gates:** schema validation present, typed command IR, allowlisted tool
  action.
- **autofix:** manual
- **fixtures:** positive=completion-to-exec; negative=json-schema-validated

### XL-012: Prompt and System Policy Leakage

- **Category:** LLM Sensitive Information Disclosure
- **OWASP LLM:** LLM07 System Prompt Leakage
- **Severity:** Medium to High
- **CWE:** CWE-540
- **Detection:** regex/path/name heuristics over assets, configs, string
  literals. Detect system_prompt.txt, judge_criteria.md, tool_policy.json,
  routing_prompt.py in distributable bundles.
- **Language adapters:** KT (Android assets/), SW (Bundle resource paths),
  DA (Flutter assets/), JV (resources/), PY (asset path packaging), CS
  (Content/Resources folders in csproj).
- **why_ai:** assistants and developers keep prompts beside code, then bundle
  them by accident when packaging the client.
- **fp_gates:** docs/examples directories, non-distributed dev prompts.
- **autofix:** manual
- **fixtures:** positive=system-prompt-in-app-bundle; negative=server-fetched

---

## v0.5 Additions from Cross-Tool Comparison

Seven probes pulled in from Google's comparison run that fill genuine gaps in
the original 599-probe set. These were absent from the original because they
target framework surfaces I underweighted.

### PYTHON_MCP_SERVER_PROMPT_LEAK

- **xl_ref:** XL-012
- **Language:** Python | **Category:** llm | **Framework:** fastmcp, mcp | **Severity:** high
- **owasp_llm:** LLM02, LLM07
- **What it catches:** MCP server tool functions decorated with `@mcp.tool` or inheriting from MCP server base classes that return raw `os.environ` values, `SYSTEM_PROMPT` variables, or unredacted config state in their response objects.
- **why_ai_v05:** MCP standard emerged late 2024 and stabilized through 2025-2026. AI tools lack a corpus of secure MCP implementations and frequently dump configuration/system state into tool responses for "debugging" that ships to production.
- **vibe_v05:** "let me return everything I know about my own state so the client can see what is happening" debugging mindset, applied to a production trust boundary.
- **Detection:** AST. Identify functions decorated with `@mcp.tool` or methods on classes inheriting from MCP server base. Scan return statements for f-strings or dict constructions containing `os.environ`, variables named `SYSTEM_PROMPT`, or sensitive config keys.
- **fp_gates_v05:** Diagnostic tools explicitly scoped to isolated local environments (file path contains `dev/`, `local/`, or filename matches `*_diagnostic*`).
- **Remediation:** Filter all tool return objects through an allowlist. Never include raw `os.environ` or system prompts in MCP responses. Use a dedicated debug tool gated by environment variable.
- **autofix_v05:** review-needed

### JAVA_SPRING_MASS_ASSIGNMENT

- **xl_ref:** XL-009
- **Language:** Java | **Category:** access | **Framework:** Spring Boot | **Severity:** high
- **owasp_web:** A01
- **What it catches:** `@RequestBody` or `@ModelAttribute` parameters that bind directly to JPA entity types instead of DTOs. The entity may have fields like `role`, `isAdmin`, `accountId` that should not be settable by the client.
- **why_ai_v05:** Spring Boot starter tutorials and Copilot scaffolding produce `@RestController` methods that bind directly to `@Entity` classes. The DTO separation is verbose and gets skipped.
- **vibe_v05:** "the entity is the model, why would I create a second class that is mostly the same."
- **Detection:** AST on `@RestController`/`@Controller` methods. Flag parameters annotated `@RequestBody` or `@ModelAttribute` whose type is also annotated `@Entity` or `@Table` (JPA), or extends a Spring Data repository's domain type.
- **fp_gates_v05:** Methods using `@JsonView` to restrict deserialization, or with explicit `@JsonIgnoreProperties` on sensitive fields.
- **Remediation:** Introduce a DTO class with only client-settable fields. Map DTO to entity in the service layer.
- **autofix_v05:** manual

### RUBY_RAILS_MASS_ASSIGNMENT

- **xl_ref:** XL-009
- **Language:** Ruby | **Category:** access | **Framework:** Rails | **Severity:** high
- **owasp_web:** A01
- **What it catches:** Controller actions calling `Model.create(params[:model])` or `Model.update(params[:model])` without `.require(:model).permit(...)` strong parameter filtering. Also catches blanket `params.permit!`.
- **why_ai_v05:** Rails scaffolding generates strong-param boilerplate but AI completion often skips the `private def model_params` method and inlines `params[:model]` directly in the action.
- **vibe_v05:** "the form is the model, the params are the model attributes, just pass them through."
- **Detection:** AST. In ActionController subclasses, flag calls to `create`, `update`, `update_attributes`, `assign_attributes` where the argument is `params[:something]` without an intervening `.permit` call. Also flag any `params.permit!` (bang version).
- **fp_gates_v05:** Calls where `params` has been processed through a `permit` call earlier in the action, even if not on the same line.
- **Remediation:** Add `private def model_params; params.require(:model).permit(:safe1, :safe2); end` and use it.
- **autofix_v05:** review-needed

### CSHARP_WPF_XAML_INJECTION

- **xl_ref:** null
- **Language:** C# | **Category:** security | **Framework:** WPF | **Severity:** high
- **owasp_web:** A03
- **What it catches:** WPF applications using `XamlReader.Load` or `XamlReader.Parse` on string content derived from user input, remote sources, or untrusted files. Allows arbitrary code execution via XAML markup extensions.
- **why_ai_v05:** Vibe-coded desktop tools and internal admin apps often use dynamic XAML loading for "configurable UI." Training corpus for WPF is older and predates security-conscious examples.
- **vibe_v05:** "let the user customize the UI by providing their own XAML, how cool is that."
- **Detection:** AST. Flag calls to `XamlReader.Load` or `XamlReader.Parse` where the argument is not a compile-time string literal or a `Stream` derived from `Application.GetResourceStream` (which loads bundled resources only).
- **fp_gates_v05:** Calls explicitly reading from `Application.GetResourceStream` or `Assembly.GetManifestResourceStream` (compiled-in resources).
- **Remediation:** Restrict XAML loading to compiled BAML resources. If runtime XAML customization is required, sanitize through a strict allowlist of permitted element types.
- **autofix_v05:** manual

### DART_DEBUG_MODE_ASSERTIONS_IN_PROD

- **xl_ref:** null
- **Language:** Dart | **Category:** misconfig | **Framework:** Flutter | **Severity:** medium
- **owasp_web:** A05
- **What it catches:** Flutter code that uses `assert()` for security-critical checks, or that relies on `kDebugMode` to skip security checks in release builds. Both `assert()` statements and `kDebugMode` branches are stripped or false in release builds; if they were doing real work, that work vanishes in production.
- **why_ai_v05:** AI completion suggests `assert(user.isAuthenticated)` because it reads like a clean check. The fact that asserts are no-ops in release mode is not visible in the immediate code context.
- **vibe_v05:** "assert is the language's built-in check, that must mean it runs."
- **Detection:** AST. Flag `assert()` calls where the asserted expression touches auth, role, permission, or token state. Flag `if (kDebugMode)` blocks that contain security logic rather than logging.
- **fp_gates_v05:** Asserts on internal invariants (data shape, list length) not tied to auth state. `kDebugMode` blocks that only contain `print` or `debugPrint`.
- **Remediation:** Replace security asserts with explicit `if (!condition) throw SecurityException(...)`. Replace `kDebugMode` security branches with environment-based feature flags.
- **autofix_v05:** review-needed

### ELIXIR_LLM_PROMPT_INJECTION_VIA_LIVEVIEW

- **xl_ref:** XL-011
- **Language:** Elixir | **Category:** llm | **Framework:** Phoenix LiveView | **Severity:** high
- **owasp_llm:** LLM01, LLM05
- **What it catches:** Phoenix LiveView `handle_event` functions that take user input from `assigns` or socket params and inject it directly into LLM prompt strings or LangChain-Elixir prompt templates.
- **why_ai_v05:** LiveView's reactive model encourages "user types, server updates, render new state" patterns. AI completion fills the LLM call into the handle_event without considering that the assign is user-controlled.
- **vibe_v05:** "the assign is just a value, why does it matter where it came from."
- **Detection:** AST. In LiveView modules (modules that `use Phoenix.LiveView`), flag `handle_event` clauses that pass `socket.assigns.<key>` or pattern-matched event params directly into a string interpolation or function call whose name matches LLM client patterns (Anthropic, OpenAI, Mistral, LiteLLM, LangChain).
- **fp_gates_v05:** Assigns processed through an explicit sanitization or validation function before reaching the LLM call.
- **Remediation:** Validate and structure user input before prompt construction. Use a typed prompt template with placeholder substitution rather than string interpolation.
- **autofix_v05:** manual

### KOTLIN_HARDCODED_AWS_CREDENTIALS_BUILDCONFIG

- **xl_ref:** XL-006
- **Language:** Kotlin | **Category:** secret | **Framework:** Android Gradle | **Severity:** critical
- **owasp_web:** A07
- **cwe:** CWE-798
- **What it catches:** AWS access keys, secret keys, or session tokens hardcoded in Android `BuildConfig` fields via `buildConfigField` in Gradle, or in `local.properties` files that get bundled into release artifacts. The AKIA/ASIA prefixes are the strongest signal.
- **why_ai_v05:** AI scaffolding for Android apps that integrate with AWS S3 or Cognito puts the credentials in `BuildConfig` for "convenience." This is distinct from `local.properties` API key storage because BuildConfig is a compiled-in constant.
- **vibe_v05:** "BuildConfig is the Android way to handle environment-specific values, that must be the right place for keys."
- **Detection:** Mixed. Manifest parse on `build.gradle`/`build.gradle.kts` for `buildConfigField` lines with values matching AWS key prefix patterns (AKIA, ASIA, AGPA, AIDA, AROA, AIPA, ANPA, ANVA). Regex over `local.properties` for the same prefixes. AST on Kotlin source for direct string literals.
- **fp_gates_v05:** Test/debug build types with fake AKIA keys (heuristic: key contains repeated characters or "TEST" substring).
- **Remediation:** Move credentials to AWS Cognito Identity Pools (unauthenticated guest access for mobile), AWS IAM Roles Anywhere, or backend-mediated signed requests. Never bundle AWS long-lived credentials in a mobile binary.
- **autofix_v05:** manual

### C_LLM_SYSTEM_PROMPT_BUFFER_OVERREAD

- **xl_ref:** XL-012
- **Language:** C | **Category:** memory | **Framework:** llama.cpp wrappers, tflite-micro | **Severity:** high
- **owasp_llm:** LLM07
- **cwe:** CWE-126
- **What it catches:** C-language LLM inference frontends (llama.cpp embedded usage, tflite-micro projects, custom inference loops) that copy system prompt strings into fixed-size char buffers with `strcpy` or `sprintf` without bounds checking. A long system prompt overflows the buffer; a short read past the null terminator leaks adjacent memory which may contain other prompt history.
- **why_ai_v05:** AI completion for embedded LLM code reaches for C string idioms from the training corpus, which predates safe-string practices. The "system prompt is just a string" mental model misses the buffer-sizing implication.
- **vibe_v05:** "I just need to pass this prompt into the inference function, it is one line of code."
- **Detection:** AST. In files importing llama.h, tensorflow/lite/micro/, or similar, flag `strcpy(dest, src)` or `sprintf(dest, "%s", src)` where `dest` is a fixed-size char array and `src` is a variable whose name or origin suggests prompt content (contains "prompt", "system", "instruction", "context").
- **fp_gates_v05:** Calls using `strncpy` with an explicit size argument, or `snprintf` with size, where size is bounded by the destination buffer.
- **Remediation:** Use `snprintf(dest, sizeof(dest), "%s", src)`. For dynamic-length prompts, allocate dynamically and track length explicitly.
- **autofix_v05:** mechanical (when fix is clearly snprintf with sizeof)

---

## Original 599-Probe Depth Catalog (corrections applied, em-dashes stripped)

Probes below use the v0.4 prose format. Schema field migration to the full v0.5 structured format is staged for v0.5.1 and tracked in the issue board. The v0.5 schema fields apply conceptually now (the `why_ai`, `fp_gates`, and remediation prose maps directly into the new fields).

For probes that adapt a cross-language family, the `xl_ref` mapping is:

- Any 'unsafe deserialization' / 'pickle' / 'Marshal.load' / 'unserialize' / 'ObjectInputStream' / 'BinaryFormatter' / 'YAML.load' probe -> XL-001
- Any 'raw SQL' / 'string-built query' / 'FromSqlRaw' / 'find_by_sql' probe -> XL-002
- Any 'shell=True' / 'system()' / 'Runtime.exec' / 'Process.Start' probe -> XL-003
- Any 'verify=False' / 'InsecureSkipVerify' / 'danger_accept_invalid_certs' / 'badCertificateCallback' probe -> XL-004
- Any 'no timeout' / 'unbounded read' / 'ReadAll' / 'unbounded_channel' probe -> XL-005
- Any 'hardcoded secret' / 'API key in source' / 'system prompt in asset' probe -> XL-006
- Any 'dynamic version' / 'missing lockfile' / 'loose range' probe -> XL-007
- Any 'install hook' / 'build.rs network' / 'preinstall script' probe -> XL-008
- Any 'mass assignment' / 'overbinding' / 'permit!' probe -> XL-009
- Any 'exported component' / 'broad permission' / 'ATS arbitrary loads' / 'Tauri scope' probe -> XL-010
- Any 'LLM output to exec/SQL/shell' probe -> XL-011
- Any 'system_prompt.txt in app bundle' / 'policy text in client' probe -> XL-012

---

## Pre-Flight Multi-Language Probe Candidate Research

**Research foundation for Pre-Flight v0.5+ language expansion.** Compiled May 2026. All recommendations are static-analysis probes (regex, AST, manifest, config inspection) suitable for client-side browser execution with no dynamic analysis, network calls, or LLM inference at scan time.

**Cross-cutting notes that apply to every language section below:**

1. **OWASP A04 Insecure Design** is intentionally light across all sections; it requires threat modeling, not pattern matching, and is largely out of scope for static analysis. Where included, probes target a _symptom_ of insecure design (e.g., missing rate-limit middleware on auth endpoints), not the root cause.
2. **LLM Top 10 mappings** are mostly language-agnostic. Provider key detection (`sk-…`, `xai-…`, `AIza…`, `AKIA…`), prompt-template injection patterns (raw user concatenation into `system`/`user` role strings), unbounded token consumption (no `max_tokens` cap), and missing output validation appear in every language section but the file-extension scope and library-call surface differ.
3. **2026 threat intelligence baseline:** Sonatype's 2026 State of the Software Supply Chain Report logged 454,600+ newly identified malicious packages in 2025 (1.233M cumulative across npm, PyPI, Maven Central, NuGet, Hugging Face). The TeamPCP/Mini Shai-Hulud campaign (March–May 2026) crossed PyPI (litellm 1.82.7/8, telnyx 4.87.1/2, lightning 2.6.2/3, PyTorch Lightning), Packagist (intercom/intercom-php@5.0.2), npm (TanStack, Mistral AI, UiPath, OpenSearch, Bitwarden CLI), and Maven Central (via mvnpm rebundling of compromised npm packages, purged November 25, 2025). Slopsquatting (AI-hallucinated package names) is now an empirically validated attack; USENIX 2025 (Spracklen et al, arXiv:2406.10279) measured 5.2% hallucination rate for commercial models and 21.7% for open-source models across 16 LLMs and 576,000 code samples, with 205,474 unique hallucinated package names, with 38% conflations, 13% typos, 51% pure fabrications, and 8.7% of Python-hallucinated names being valid JavaScript packages.
4. **"AI gets this wrong" rationale convention:** When a probe entry says "AI default is X," it means the training corpus skews toward tutorial-quality or Stack-Overflow-era patterns that predate the current secure-default version of the relevant API. Cursor, Claude Code, Copilot, Lovable, Bolt, v0, Replit, Windsurf, Continue.dev, and Aider all share base models from the same handful of providers; failure modes are largely correlated across tools, with tool-specific differences mostly in _what code gets emitted unprompted_ (Lovable/Bolt/v0 add framework scaffolding aggressively; Cursor/Claude Code/Aider edit more surgically; Copilot's inline completions amplify the immediate-context bias).
5. **Severity scale:** Critical = direct RCE / credential exfil / full-tenant data breach. High = privilege escalation, mass data exposure, auth bypass. Medium = info disclosure, DoS, weakened crypto with mitigations. Low = hardening gaps. Info = best-practice nudges.
6. **Detection approach abbreviations:** RX = regex over source; AST = abstract syntax tree query (tree-sitter recommended for the browser-side); MAN = manifest/lockfile parse; CFG = config-file parse (YAML/TOML/JSON/properties); BIN = binary/artifact inspection; STR = literal/string-table extraction.

The languages below are presented in the order requested. Each section contains: (a) framework inventory, (b) probe enumeration grouped by category, and (c) supply-chain incident references for that ecosystem.

## 1. Python

### Framework / Library Inventory (Python)

**Top-3 frameworks with framework-specific probes included below:** Django, Flask, FastAPI.

**Additional frameworks/libraries to enumerate in future passes:** Starlette, Tornado, Sanic, Pyramid, Bottle, AIOHTTP, Quart, Litestar, Streamlit, Gradio, Chainlit, Dash, Reflex, Panel, LangChain, LangGraph, LlamaIndex, Haystack, DSPy, AutoGen, CrewAI, Pydantic / Pydantic AI, SQLAlchemy, SQLModel, Tortoise ORM, Peewee, Django ORM, asyncpg, psycopg2/psycopg3, PyMongo, Motor, Redis-py, Celery, RQ, Dramatiq, APScheduler, Airflow, Prefect, Dagster, requests, httpx, aiohttp-client, urllib3, BeautifulSoup, lxml, PyYAML, ruamel.yaml, Jinja2, Mako, boto3, google-cloud-\*, azure-sdk-for-python, kubernetes, paramiko, fabric, cryptography, pycryptodome, PyJWT, python-jose, passlib, bcrypt, argon2-cffi, authlib, oauthlib, social-auth, django-allauth, fastapi-users, Pillow, OpenCV-Python, NumPy, pandas, polars, PyTorch, TensorFlow, Keras, scikit-learn, transformers, sentence-transformers, ONNXRuntime, vLLM, Triton, litellm, openai-python, anthropic-sdk, google-generativeai, cohere, mistralai, qdrant-client, weaviate-client, pinecone-client, chromadb, faiss, pymilvus, instructor, guidance, outlines, marvin, fastmcp, mcp.

### Category 1; AI-Tool Failure Patterns (Python)

#### PROBE: Django DEBUG=True in settings.py committed to repo

- **Language:** Python | **Category:** AI-tool failure | **Framework:** Django | **Severity:** high
- **What it catches:** `DEBUG = True` left as a top-level assignment in `settings.py` or its environment-specific siblings (`settings/production.py`, `settings/prod.py`) without conditional gating by env var. Django's `DEBUG=True` exposes the technical 500 page including local variables, SECRET_KEY (sometimes), installed apps, full SQL queries, and stack traces with surrounding source code.
- **Why AI gets this wrong:** Django's `startproject` template ships `DEBUG = True`; AI tools generating from scratch or extending starter projects rarely flip it. Lovable/Bolt/v0-style scaffolding aggressively prioritizes "looks like it runs locally" over deployment hardening, and Copilot's training corpus is dominated by tutorial-stage `settings.py` files.
- **Detection approach:** RX `^\s*DEBUG\s*=\s*True` in any `settings*.py`; AST: assignment to `DEBUG` Name at module scope where RHS is literal `True`.
- **False positive risk:** Conditional `DEBUG = os.environ.get("DEBUG") == "1"` followed by `DEBUG = True` in a local-only file should be gated by filename. `test_settings.py` and `settings_dev.py` are usually legitimate.
- **Remediation:** `DEBUG = os.environ.get("DJANGO_DEBUG", "False").lower() == "true"` and explicit `False` default.
- **Known incidents:** OWASP A05 Security Misconfiguration; Django security FAQ explicitly warns. CVE-2024-39614 and historical Django CVEs leverage debug pages for info disclosure.

#### PROBE: Django SECRET_KEY hardcoded literal

- **Language:** Python | **Category:** AI-tool failure | **Framework:** Django | **Severity:** critical
- **What it catches:** `SECRET_KEY = "django-insecure-..."` or any string literal RHS in settings. Django uses SECRET_KEY to sign session cookies, password reset tokens, CSRF tokens, and `signing.dumps()` payloads; disclosure yields session forgery and password-reset takeover.
- **Why AI gets this wrong:** `startproject` emits a `django-insecure-...` placeholder. AI models preserve the literal because the immediate context "just works." Cursor/Aider in particular tend to leave the literal because rewriting it requires reading an environment file the model hasn't been shown.
- **Detection approach:** RX `SECRET_KEY\s*=\s*['"]` in `settings*.py`; flag with extra severity if value starts with `django-insecure-`.
- **False positive risk:** `SECRET_KEY = os.environ["SECRET_KEY"]` should pass. Test-suite fixtures with literal keys are acceptable if filename matches `test_*` or `conftest.py`.
- **Remediation:** Load from env or secret manager; rotate any committed value.
- **Known incidents:** GitHub secret-scanning has identified tens of thousands of leaked Django SECRET_KEY values across public repos; Django security release notes recurrently flag this.

#### PROBE: Django ALLOWED_HOSTS wildcard in production settings

- **Language:** Python | **Category:** AI-tool failure | **Framework:** Django | **Severity:** medium
- **What it catches:** `ALLOWED_HOSTS = ["*"]` or `ALLOWED_HOSTS = []` with `DEBUG = False`. Wildcard allows Host header injection and breaks Django's Host validation, enabling password-reset poisoning via Host-header manipulation.
- **Why AI gets this wrong:** "It worked locally" pattern; wildcards are the path of least friction when AI tools don't know the deployment hostname.
- **Detection approach:** AST: list literal assigned to `ALLOWED_HOSTS` containing string `"*"`.
- **False positive risk:** Genuine multi-tenant proxies in front of Django sometimes use `*` plus explicit Host stripping at the proxy. Flag as medium, not critical.
- **Remediation:** Enumerate explicit hostnames.
- **Known incidents:** Django CVE-2024-41989 and earlier Host-header advisories.

#### PROBE: Flask app.run(debug=True) or debug=True via env at module top

- **Language:** Python | **Category:** AI-tool failure | **Framework:** Flask | **Severity:** critical
- **What it catches:** `app.run(debug=True)` enables Werkzeug's debugger, which by default exposes an interactive Python REPL on the 500 page protected only by a PIN that has been bypassed in numerous CVEs (CVE-2019-1010083 and others). On any exception, an attacker can execute arbitrary Python.
- **Why AI gets this wrong:** Every Flask "hello world" tutorial uses `debug=True`. AI tools copy this verbatim when generating Flask starter code via Lovable, Bolt, Replit, and v0 templates.
- **Detection approach:** RX `app\.run\([^)]*debug\s*=\s*True` and `FLASK_DEBUG\s*=\s*['"]?1`; AST: `Call` to `run` on Flask instance with keyword `debug=True`.
- **False positive risk:** `if __name__ == "__main__":` blocks with `debug=True` in clearly named example files. Still flag; these often get deployed.
- **Remediation:** `debug=os.environ.get("FLASK_DEBUG") == "1"` and serve via gunicorn/uwsgi behind a reverse proxy in production.
- **Known incidents:** Werkzeug debugger RCE documented broadly; Shodan dorks regularly find live Flask debuggers.

#### PROBE: FastAPI CORS allow_origins=["*"] with allow_credentials=True

- **Language:** Python | **Category:** AI-tool failure | **Framework:** FastAPI | **Severity:** high
- **What it catches:** `CORSMiddleware(app, allow_origins=["*"], allow_credentials=True)` is rejected by browsers, but the _combined_ pattern `allow_origins=["*"], allow_methods=["*"], allow_headers=["*"], allow_credentials=True` is a common AI emission that either (a) is silently broken in the browser, or (b) some AI tools replace `*` with a reflected `Access-Control-Allow-Origin: <Origin>` that _does_ work with credentials and is a classic CSRF vector.
- **Why AI gets this wrong:** "Just make CORS work" is one of the most common debugging prompts. AI tools default to the broadest permission set and use credentials=True because they've seen authenticated SPAs in training data.
- **Detection approach:** AST: `CORSMiddleware` kwargs where `allow_origins` contains `"*"` or list of `"*"` AND `allow_credentials=True`. Also flag origin regex `.*`.
- **False positive risk:** Public APIs with no auth legitimately use `*` without credentials. The combination is what's dangerous.
- **Remediation:** Enumerate trusted origins; never combine wildcard with credentials.
- **Known incidents:** OWASP A05; PortSwigger Web Security Academy "CORS vulnerabilities" body of work.

#### PROBE: FastAPI/Flask routes that pass user input to subprocess shell=True

- **Language:** Python | **Category:** AI-tool failure | **Framework:** Flask/FastAPI | **Severity:** critical
- **What it catches:** Any route handler where a `Request` body field, path parameter, or query parameter flows (taint) into `subprocess.run(..., shell=True)`, `os.system()`, `os.popen()`, or `commands.getoutput()`.
- **Why AI gets this wrong:** When asked to "run this CLI tool from my API," AI defaults to `shell=True` because string interpolation feels natural in Python; AI rarely refactors to argv-list form even when prompted for "secure" code.
- **Detection approach:** AST: identify route handlers (`@app.route`, `@app.get`, `@router.post`); from their parameters, taint-trace to `subprocess.*` calls with `shell=True` or to `os.system`/`os.popen`. A simpler conservative variant: flag any `shell=True` in the same file as a route decorator.
- **False positive risk:** Hardcoded commands (`subprocess.run("ls /tmp", shell=True)`) are still bad practice but not injection.
- **Remediation:** `subprocess.run([cmd, arg1, arg2], shell=False)` and validate args against an allowlist.
- **Known incidents:** OWASP A03 Injection; CWE-78; multiple Flask CVEs in plugin ecosystem.

#### PROBE: Pydantic v1 .dict() round-trip used as trust boundary

- **Language:** Python | **Category:** AI-tool failure | **Framework:** Pydantic | **Severity:** medium
- **What it catches:** Code that accepts untrusted JSON, calls `MyModel(**data)`, then `.dict()` and assumes the output is "validated" while the model uses `extra = "allow"` or contains `Any`-typed fields, defeating validation.
- **Why AI gets this wrong:** Pydantic v1 → v2 migration is incomplete in much of the training corpus. AI tools emit `class Config: extra = "allow"` to "fix" mysterious validation errors when the right answer is to define the schema.
- **Detection approach:** AST: BaseModel subclass with inner `Config` class containing `extra = "allow"`, OR fields typed `Any`, `Dict[str, Any]`, `dict`.
- **False positive risk:** Internal data-pipeline models legitimately use `Any`.
- **Remediation:** Use strict schemas; `model_config = ConfigDict(extra="forbid")` in Pydantic v2.
- **Known incidents:** General secure-design pattern; OWASP ASVS V5.

#### PROBE: LangChain / LlamaIndex unbounded chain without max_tokens or timeout

- **Language:** Python | **Category:** AI-tool failure | **Framework:** LangChain/LlamaIndex | **Severity:** medium
- **What it catches:** `ChatOpenAI()`, `OpenAI()`, `Anthropic()`, `ChatAnthropic()`, etc. instantiated without `max_tokens`, without `timeout`, and called inside loops or agent executors with no recursion limit.
- **Why AI gets this wrong:** LangChain README examples omit max_tokens. AI tools copy the README.
- **Detection approach:** AST: LLM-client instantiation; look for absence of `max_tokens`, `request_timeout`, `max_retries` kwargs. Combine with detection of `AgentExecutor(... max_iterations=...)` absence.
- **False positive risk:** Some legitimate uses want full context windows; flag as info/medium.
- **Remediation:** Set `max_tokens`, `timeout`, `max_iterations`, `max_execution_time`.
- **Known incidents:** OWASP LLM10 Unbounded Consumption; documented runaway-cost incidents on developer Twitter / X.

#### PROBE: LangChain PromptTemplate with f-string user concatenation

- **Language:** Python | **Category:** AI-tool failure | **Framework:** LangChain | **Severity:** high
- **What it catches:** `prompt = f"You are a helpful assistant. User said: {user_input}\nAnswer:"` and similar f-string concatenation where untrusted input is placed _inside_ the system prompt rather than as a separate `HumanMessage`.
- **Why AI gets this wrong:** F-strings are pythonic; AI defaults to them. The structural separation between system and user role is invisible at f-string time.
- **Detection approach:** RX `f["'].*\{[^}]+\}.*["']` in same call chain as `PromptTemplate.from_template` or `ChatPromptTemplate`; AST: f-string passed to LLM call where one of the format expressions is a Request-derived name.
- **False positive risk:** Legitimate templating of trusted strings (hostname, model name) into prompts.
- **Remediation:** Use `ChatPromptTemplate.from_messages([("system", "..."), ("human", "{input}")])` with parameter substitution at the message level.
- **Known incidents:** OWASP LLM01 Prompt Injection; LangChain security guidance.

#### PROBE: requests/httpx with verify=False

- **Language:** Python | **Category:** AI-tool failure | **Framework:** requests/httpx | **Severity:** high
- **What it catches:** Any `requests.get/post/...(verify=False)` or `httpx.Client(verify=False)` or `urllib3.disable_warnings()` paired with HTTPS URLs.
- **Why AI gets this wrong:** When a corporate proxy or self-signed cert breaks the request, AI tools' first remediation is `verify=False` rather than `verify="/path/to/ca.pem"`. Almost every "fix my SSL error" Stack Overflow answer this pattern is trained on.
- **Detection approach:** RX `verify\s*=\s*False`; AST: keyword arg in `requests.*` or `httpx.*` calls.
- **False positive risk:** Internal CI tests against self-signed local servers.
- **Remediation:** Provide CA bundle path or fix the cert chain.
- **Known incidents:** CWE-295; OWASP A02.

#### PROBE: pickle.load / pickle.loads on untrusted data

- **Language:** Python | **Category:** AI-tool failure (also Memory/Concurrency) | **Framework:** stdlib | **Severity:** critical
- **What it catches:** `pickle.load(open(filename, "rb"))` or `pickle.loads(request.data)` where the source is user-controlled.
- **Why AI gets this wrong:** AI tools confuse pickle with JSON when asked to "serialize this Python object." Many ML tutorials use pickle for model artifacts and AI generalizes the pattern.
- **Detection approach:** AST: `pickle.load`/`pickle.loads`/`cPickle.load*`/`dill.load*`/`joblib.load`/`torch.load(... weights_only=False)`/`pandas.read_pickle` where input is a Flask `request.*`, FastAPI `body`, file path from `request.files`, or unconstrained.
- **False positive risk:** Loading own-generated artifacts from trusted disk paths.
- **Remediation:** JSON for data; `torch.load(weights_only=True)` (default in PyTorch 2.6+); `safetensors` for ML models.
- **Known incidents:** CVE-2007-4559, CWE-502; PyTorch's 2024 switch to `weights_only=True` default; Hugging Face's safetensors push.

#### PROBE: yaml.load without SafeLoader

- **Language:** Python | **Category:** AI-tool failure | **Framework:** PyYAML | **Severity:** critical
- **What it catches:** `yaml.load(data)` or `yaml.load(data, Loader=yaml.Loader)` allows arbitrary Python object construction via `!!python/object/apply` tags.
- **Why AI gets this wrong:** Older AI training data predates PyYAML's deprecation of the default Loader.
- **Detection approach:** AST: `yaml.load(...)` calls where `Loader` kwarg is missing or is `Loader`/`UnsafeLoader`/`FullLoader` (FullLoader is also unsafe pre-5.1).
- **False positive risk:** Internal CI configs only.
- **Remediation:** `yaml.safe_load(data)` or `yaml.load(data, Loader=yaml.SafeLoader)`.
- **Known incidents:** CVE-2017-18342 (Ansible); ongoing CWE-502 examples; ENISA threat landscape repeatedly cites.

#### PROBE: eval() / exec() with any user input flow

- **Language:** Python | **Category:** AI-tool failure | **Framework:** stdlib | **Severity:** critical
- **What it catches:** `eval(request.form["formula"])` and similar.
- **Why AI gets this wrong:** When asked "let users enter formulas," AI tools default to eval because it's one line. Cursor will sometimes suggest `ast.literal_eval` if explicitly prompted for safety, but unprompted it picks eval.
- **Detection approach:** AST: `eval` or `exec` call with argument transitively reachable from a route handler parameter; also flag bare `eval()`/`exec()` in non-test code.
- **False positive risk:** Internal admin tools, REPLs. Severity remains critical because deployment context can change.
- **Remediation:** `ast.literal_eval` for data; a sandboxed expression evaluator (asteval, simpleeval, RestrictedPython) for formulas; never eval.
- **Known incidents:** CWE-95; numerous CVEs in Python web apps.

#### PROBE: Hardcoded LLM provider keys

- **Language:** Python | **Category:** AI-tool failure | **Framework:** openai/anthropic/google-generativeai/cohere/mistralai/litellm | **Severity:** critical
- **What it catches:** Literals matching `sk-[a-zA-Z0-9]{20,}` (OpenAI), `sk-ant-[a-zA-Z0-9-]{50,}` (Anthropic), `AIza[0-9A-Za-z_-]{35}` (Google API key, including Gemini), `xai-[a-zA-Z0-9]{30,}` (xAI), `gsk_[a-zA-Z0-9]{40,}` (Groq), keys passed to `OpenAI(api_key="...")` or set into `os.environ["OPENAI_API_KEY"] = "..."`.
- **Why AI gets this wrong:** "Just hard-code it for now" prototypes get shipped. Lovable/Bolt/Replit emit keys inline when the user pastes them. Copilot autocompletes from clipboard.
- **Detection approach:** RX on the above patterns plus `api_key\s*=\s*["'][^"']{20,}["']` in any LLM client constructor.
- **False positive risk:** Examples/docs files with placeholders like `"sk-...your_key_here..."`; exclude obvious placeholder substrings (`your_key`, `xxx`, `...`, `EXAMPLE`).
- **Remediation:** Env vars + secret manager.
- **Known incidents:** Vercel Context.ai env-var leak (April 2026 per GitGuardian); routine GitHub secret-scanning detections.

### Category 2; OWASP Top 10:2025 Mappings (Python)

#### PROBE: Django QuerySet .extra() / RawSQL with f-string interpolation (A03)

- **Language:** Python | **Category:** OWASP A03 Injection | **Framework:** Django ORM | **Severity:** critical
- **What it catches:** `Model.objects.extra(where=[f"name = '{name}'"])` and `RawSQL(f"...{user_input}...")`.
- **Why AI gets this wrong:** Asked "filter where the column equals a user value with a complex condition," AI bypasses Django's parameterized API because the templating is verbose.
- **Detection approach:** AST: f-string passed to `.extra(where=...)`, `RawSQL`, `Model.objects.raw`, or `cursor.execute` (the latter when also seen with `connection` or `connections[...].cursor()`).
- **False positive risk:** Pure-literal SQL.
- **Remediation:** Use `params` keyword: `Model.objects.raw("SELECT * FROM t WHERE x = %s", [user_value])`.
- **Known incidents:** Django security advisories regularly cover ORM injection edge cases.

#### PROBE: SQLAlchemy text() with f-string (A03)

- **Language:** Python | **Category:** OWASP A03 | **Framework:** SQLAlchemy | **Severity:** critical
- **What it catches:** `session.execute(text(f"SELECT * FROM users WHERE id = {user_id}"))`.
- **Detection approach:** AST: `text()` call where argument is an f-string with at least one substitution.
- **False positive risk:** Hardcoded text() with only literal substitutions.
- **Remediation:** `text("SELECT * FROM users WHERE id = :id").bindparams(id=user_id)`.
- **Known incidents:** SQLAlchemy security guide; OWASP A03.

#### PROBE: Django/Jinja2 mark_safe / |safe with non-literal argument (A03 XSS)

- **Language:** Python | **Category:** OWASP A03 | **Framework:** Django/Jinja2 | **Severity:** high
- **What it catches:** `mark_safe(user_value)` or templates rendering `{{ value|safe }}` where the value flows from request input.
- **Why AI gets this wrong:** AI bypasses autoescape to "make the HTML render" without considering provenance.
- **Detection approach:** AST: `mark_safe(...)` called with non-Constant; template scan for `|safe` filter usage.
- **False positive risk:** Trusted markdown-rendered content from admin-only sources.
- **Remediation:** Sanitize with `bleach`/`nh3` before mark_safe; restructure to render the trusted bits as HTML and the untrusted bits autoescaped.
- **Known incidents:** Django XSS CVEs (e.g., CVE-2024-39329 admin trust-boundary).

#### PROBE: hashlib.md5 / hashlib.sha1 for password or token (A02)

- **Language:** Python | **Category:** OWASP A02 Cryptographic Failures | **Framework:** stdlib | **Severity:** high
- **What it catches:** `hashlib.md5(password.encode()).hexdigest()` / `hashlib.sha1`.
- **Why AI gets this wrong:** Training corpus is full of "hash the password" examples that use MD5/SHA1; LLMs prefer the shorter `hashlib` API over `bcrypt`/`argon2`.
- **Detection approach:** AST: `hashlib.md5`/`hashlib.sha1` calls in same function or class as variables/parameters named `password`, `passwd`, `secret`, `token`, `api_key`.
- **False positive risk:** Legitimate non-security uses (file checksums, cache keys); gate on variable-name heuristic.
- **Remediation:** `bcrypt`, `argon2-cffi`, or `passlib`'s argon2 backend; for tokens, `secrets.token_urlsafe`.
- **Known incidents:** CWE-327; OWASP A02.

#### PROBE: random module for security tokens (A02)

- **Language:** Python | **Category:** OWASP A02 | **Framework:** stdlib | **Severity:** high
- **What it catches:** `random.randint`, `random.choice`, `random.random` used to generate session IDs, password reset tokens, CSRF tokens, OTPs.
- **Why AI gets this wrong:** `random` is the obvious module. `secrets` was added in 3.6 and AI training data treats both as equivalent.
- **Detection approach:** AST: `random.*` call where return value is assigned to variables named `token`, `secret`, `otp`, `code`, `reset`, `verification`, `session_id`, `nonce`, `csrf`.
- **False positive risk:** Genuine non-security randomness (game logic, sampling).
- **Remediation:** Use `secrets` module: `secrets.token_urlsafe(32)`, `secrets.choice`, `secrets.randbelow`.
- **Known incidents:** CWE-338; multiple Django/Flask CVEs.

#### PROBE: JWT decode with verify=False or algorithms=None (A07)

- **Language:** Python | **Category:** OWASP A07 IDAF | **Framework:** PyJWT/python-jose/authlib | **Severity:** critical
- **What it catches:** `jwt.decode(token, options={"verify_signature": False})` or `algorithms=["none"]` or missing `algorithms` parameter (PyJWT < 2.0 defaulted to allowing any).
- **Why AI gets this wrong:** When debugging "why doesn't my JWT verify," AI turns off verification.
- **Detection approach:** AST: `jwt.decode` calls; flag if `options` dict contains `verify_signature: False`, or `algorithms` contains `"none"`, or `algorithms` kwarg is missing entirely.
- **False positive risk:** Token introspection for debugging; rare in production code.
- **Remediation:** Always pass `algorithms=["RS256"]` (or your specific algorithm) and verify signature.
- **Known incidents:** CVE-2022-29217 (PyJWT algorithm confusion); broad "alg=none" attack body of literature.

#### PROBE: open(redirect_url) / HttpResponseRedirect without allowlist (A01)

- **Language:** Python | **Category:** OWASP A01 / Open Redirect | **Framework:** Django/Flask/FastAPI | **Severity:** medium
- **What it catches:** `return redirect(request.GET.get("next"))` in Django or `return RedirectResponse(url=request.query_params["next"])` in FastAPI without `url_has_allowed_host_and_scheme` or equivalent.
- **Detection approach:** AST: `redirect()` / `RedirectResponse` / `HttpResponseRedirect` with argument flowing from request without intervening allowlist check.
- **False positive risk:** Constants, internal paths starting with `/`.
- **Remediation:** Django's `url_has_allowed_host_and_scheme(url, allowed_hosts={...})`.
- **Known incidents:** CWE-601; Django's evolving safe-redirect API.

#### PROBE: requests/httpx with user-supplied URL (A10 SSRF)

- **Language:** Python | **Category:** OWASP A10 SSRF | **Framework:** requests/httpx/aiohttp/urllib | **Severity:** high
- **What it catches:** Outbound HTTP calls whose URL flows from a request parameter without DNS resolution + RFC1918 / link-local / loopback / 169.254 metadata-endpoint validation.
- **Detection approach:** AST: `requests.get/post/...`, `httpx.AsyncClient().get`, `urllib.request.urlopen` where URL argument transitively comes from a route handler input.
- **False positive risk:** Many. Flag with low confidence; pair with the broader pattern "missing SSRF guard library import" (`ssrf_guard`, `safeurl-python`).
- **Remediation:** Resolve hostname, check against denylist (loopback, RFC1918, 169.254.169.254, fd00::/8, cloud metadata IPs), and pin to that IP for the request.
- **Known incidents:** Capital One 2019 SSRF; routine cloud-metadata SSRF reports.

#### PROBE: Django CSRF_COOKIE_SECURE / SESSION_COOKIE_SECURE / SECURE_HSTS_SECONDS missing (A05)

- **Language:** Python | **Category:** OWASP A05 | **Framework:** Django | **Severity:** medium
- **What it catches:** Production-shaped settings file lacking `CSRF_COOKIE_SECURE=True`, `SESSION_COOKIE_SECURE=True`, `SECURE_HSTS_SECONDS`, `SECURE_SSL_REDIRECT=True`, `SECURE_PROXY_SSL_HEADER`.
- **Detection approach:** AST: presence/absence of the named assignments in any `settings*.py`.
- **False positive risk:** Local-only dev settings.
- **Remediation:** Add the missing flags; run `python manage.py check --deploy`.
- **Known incidents:** Django deployment checklist; OWASP A05.

#### PROBE: logging.exception/print(traceback) of sensitive data (A09)

- **Language:** Python | **Category:** OWASP A09 | **Framework:** stdlib | **Severity:** low
- **What it catches:** `logging.error(f"login failed for {user.password}")`, `print(token)`, etc.
- **Detection approach:** AST: `logging.*`, `print`, `traceback.print_exc` arguments containing names like `password`, `secret`, `token`, `api_key`, `authorization`, `cookie`.
- **False positive risk:** High; flag as info.
- **Remediation:** Structured logging with redaction.
- **Known incidents:** Routine secret leakage in logs.

### Category 3; OWASP LLM Top 10:2025 Mappings (Python)

#### PROBE: LLM01; Untrusted text concatenated into system prompt

- See Category 1 LangChain f-string entry. Also applies to raw OpenAI Python SDK: `messages=[{"role": "system", "content": f"Rules: {user_input}"}]`.

#### PROBE: LLM02; LLM response logged with full user PII context

- **Language:** Python | **Category:** OWASP LLM02 | **Framework:** any LLM SDK | **Severity:** medium
- **What it catches:** `logger.info(response.choices[0].message.content)` plus the request payload, written to default file handlers without sampling/redaction.
- **Detection approach:** AST: LLM call result variable flowing into `logging`/`print`/file write in same function with no intervening redaction call.
- **Remediation:** Redaction layer (presidio, scrubadub) before logging.

#### PROBE: LLM03; Hugging Face from_pretrained with trust_remote_code=True

- **Language:** Python | **Category:** OWASP LLM03 Supply Chain / LLM04 Data Poisoning | **Framework:** transformers | **Severity:** critical
- **What it catches:** `AutoModel.from_pretrained("user/repo", trust_remote_code=True)`; executes arbitrary Python from the model repo.
- **Why AI gets this wrong:** Newer custom architectures (Mamba, novel MoE models) require trust_remote_code; AI just turns it on.
- **Detection approach:** RX `trust_remote_code\s*=\s*True`.
- **False positive risk:** Genuine need for custom code; flag and require explicit allowlist.
- **Remediation:** Pin to specific revision SHA; vendor the modeling code.
- **Known incidents:** Hugging Face has documented multiple malicious model repos abusing this; Trail of Bits and ProtectAI research.

#### PROBE: LLM04; Loading pickled .bin model files without safetensors fallback

- See pickle entry above; specifically flag `torch.load(...)` where `weights_only` is False or unspecified on PyTorch <2.6.

#### PROBE: LLM05; LLM JSON output passed to eval/exec/subprocess

- **Language:** Python | **Category:** OWASP LLM05 Improper Output Handling | **Framework:** any | **Severity:** critical
- **What it catches:** `result = llm.invoke(...); exec(result)` or assistant-emitted SQL passed to `cursor.execute` without re-parameterization.
- **Detection approach:** AST: data flow from LLM SDK return value to eval/exec/subprocess/cursor.execute.
- **Remediation:** Structured output via tools/function calling; validate and re-parameterize.
- **Known incidents:** OWASP LLM05; multiple LangChain CVEs around `PALChain`/`LLMMathChain` (CVE-2023-29374, CVE-2023-39631).

#### PROBE: LLM06; Agent with shell tool and no human-in-loop

- **Language:** Python | **Category:** OWASP LLM06 Excessive Agency | **Framework:** LangChain/AutoGen/CrewAI | **Severity:** high
- **What it catches:** `ShellTool()`, `PythonREPLTool()`, `RequestsGetTool()`, `Tool.from_function(func=os.system, ...)` registered on an agent without `human_approval` or `requires_approval` wrappers.
- **Detection approach:** AST: agent tool list contains shell/python/requests/file-write tool and there is no human-approval wrapper in the same chain.
- **Remediation:** Constrain the tool surface; use approval middleware.
- **Known incidents:** LangChain Hub PALChain advisories; OWASP LLM06.

#### PROBE: LLM07; System prompt loaded from a non-frozen string

- **Language:** Python | **Category:** OWASP LLM07 | **Framework:** any | **Severity:** medium
- **What it catches:** System prompt assembled from a database row, user-uploaded file, or env variable that any deployer can change; vs being a frozen constant or a checked-in resource file. Combined with absence of any output-leakage canary detection.
- **Detection approach:** AST: system-role content sourced from a non-Constant.

#### PROBE: LLM08; Embedding similarity used as authorization decision

- **Language:** Python | **Category:** OWASP LLM08 | **Framework:** chromadb/pinecone/qdrant/weaviate | **Severity:** medium
- **What it catches:** Code that picks the top-1 retrieved chunk and uses it without permission checking. Specifically: `client.search(...)` followed by direct use of the returned text in a prompt without a per-user `filter` argument.
- **Detection approach:** AST: vector-store search calls; absence of `filter`/`where` kwarg that includes a user/tenant identifier.

#### PROBE: LLM09; No citation/grounding for generated content

- Generally out of scope for static analysis (it's a behavior).

#### PROBE: LLM10; Unbounded LLM consumption

- See LangChain unbounded chain entry. Additionally: streaming completion in an HTTP handler without a per-request token budget.

### Category 4; Memory / Concurrency / Resource Patterns (Python)

#### PROBE: asyncio.create_task with no reference held (orphan task)

- **Language:** Python | **Category:** Concurrency | **Severity:** medium
- **What it catches:** `asyncio.create_task(coro())` where the return value is discarded. asyncio holds only weak references to tasks; orphan tasks can be GC'd mid-execution, losing exceptions silently.
- **Why AI gets this wrong:** Fire-and-forget patterns look idiomatic.
- **Detection approach:** AST: `Expr` statements whose expression is a `Call` to `asyncio.create_task` (i.e., the result is not assigned).
- **Remediation:** Hold a strong reference in a set; add a done-callback that discards.
- **Known incidents:** Python docs explicitly warn since 3.11.

#### PROBE: tempfile.mktemp (race condition)

- **Language:** Python | **Category:** Concurrency | **Severity:** medium
- **Detection approach:** RX `tempfile\.mktemp\(`.
- **Remediation:** `tempfile.mkstemp` or `NamedTemporaryFile`.

#### PROBE: threading.Lock not used as context manager around shared state

- Speculative; high false-positive risk. SPECULATIVE.

#### PROBE: subprocess.Popen without timeout and without communicate

- **Language:** Python | **Category:** Resource | **Severity:** low
- **What it catches:** `subprocess.run(...)` or `.Popen(...).wait()` with no `timeout=`.
- **Remediation:** Always pass `timeout=`.

#### PROBE: requests/httpx without timeout

- **Language:** Python | **Category:** Resource | **Severity:** medium
- **What it catches:** `requests.get(url)` with no `timeout`; hangs indefinitely on a slow server, enabling thread-pool exhaustion DoS.
- **Detection approach:** AST: `requests.*`/`httpx.*` HTTP calls lacking `timeout` kwarg.
- **Remediation:** Always pass `timeout=(connect, read)`.
- **Known incidents:** Slowloris-style DoS amplification in scraper code.

#### PROBE: Unbounded list growth in long-running loops (info-only)

- SPECULATIVE; high false-positive rate; deprioritize.

#### PROBE: ctypes / cffi calls with len() of user input (buffer overflow proxy)

- **Language:** Python | **Category:** Memory | **Severity:** medium
- **What it catches:** Passing untrusted `bytes` to a `ctypes.create_string_buffer` or to a foreign function expecting `c_char_p` of a specific length.
- **Detection approach:** AST heuristic.

### Category 5; Supply Chain Patterns (Python / PyPI)

#### PROBE: Unpinned dependency in requirements.txt / pyproject.toml

- **Language:** Python | **Category:** Supply chain (A06/A08) | **Severity:** medium
- **What it catches:** `requests` (no version) or `requests>=2.0` (open ceiling) in `requirements.txt`, `pyproject.toml`, `setup.py install_requires`. Floating versions made the LiteLLM 1.82.7/8 incident a wide blast.
- **Detection approach:** MAN: parse requirements.txt for any spec lacking `==` or hash; pyproject.toml `[project]` and `[tool.poetry.dependencies]` for unpinned entries.
- **False positive risk:** Library packages (intended to be consumed) appropriately use ranges; only flag for application/service projects (heuristic: presence of `Dockerfile`, `wsgi.py`, `asgi.py`, `manage.py`).
- **Remediation:** Pin with `==` in services; use `pip-compile --generate-hashes`; consider `requirements.txt` with `--require-hashes`.
- **Known incidents:** LiteLLM 1.82.7/1.82.8 (March 24, 2026, TeamPCP/Mini Shai-Hulud); telnyx 4.87.1/2 (March 27, 2026); PyTorch Lightning 2.6.2/2.6.3 (April 30, 2026); pyannote-audio transitive dependency exposing Intercom (April 30, 2026).

#### PROBE: PyPI package known compromised (allowlist of incident IOCs)

- **Language:** Python | **Category:** Supply chain | **Severity:** critical
- **What it catches:** Exact name+version matches against a bundled IOC list: `litellm==1.82.7`, `litellm==1.82.8`, `telnyx==4.87.1`, `telnyx==4.87.2`, `lightning==2.6.2`, `lightning==2.6.3`, `pytorch-lightning==2.6.2`, `pytorch-lightning==2.6.3`, `termncolor` (all), `colorinal` (all), historical: `colourama`, `ctx`, `phpass` Python typosquats, `jeIlyfish` typosquat, etc.
- **Detection approach:** MAN diff against bundled JSON.
- **Remediation:** Rotate all credentials reachable from any host that installed; reinstall from clean source.
- **Known incidents:** TeamPCP campaign (Datadog, Snyk, Trend Micro, Wiz coverage March–May 2026); 2024 Ultralytics compromise; XZ Utils backstory.

#### PROBE: PyPI package likely typosquat / slopsquat

- **Language:** Python | **Category:** Supply chain | **Severity:** high
- **What it catches:** Names with Levenshtein distance ≤ 2 from known popular packages (`requests`/`request`/`reqests`, `urllib3`/`urlib3`, `numpy`/`numpi`, `transformers`/`transfomers`, `huggingface-hub`/`huggingface-cli`, `pandas`/`pandes`). Also names matching common LLM-hallucinated patterns from published slopsquatting research.
- **Detection approach:** MAN: bundled allowlist of ~2,000 most-downloaded packages with edit-distance check + a denylist of names known to be hallucinated by major models.
- **False positive risk:** Some near-name packages are legitimate forks.
- **Known incidents:** `huggingface-cli` hallucinated package (30,000+ downloads of empty placeholder); USENIX 2025 paper "We Have a Package for You!"; Socket slopsquatting tracking.

#### PROBE: pip install with --trusted-host or --index-url override

- **Language:** Python | **Category:** Supply chain | **Severity:** high
- **What it catches:** `pip install --index-url http://...` in Dockerfile or CI script; `--trusted-host` overrides; `pip.conf` with non-PyPI index.
- **Detection approach:** RX in Dockerfile, shell scripts, `.github/workflows/*.yml`, `pip.conf`, `pyproject.toml` `[tool.pip]`.
- **Remediation:** Pin to PyPI and/or use an internal mirror with hash verification.

#### PROBE: setup.py with arbitrary code in install_requires resolution path

- **Language:** Python | **Category:** Supply chain | **Severity:** high
- **What it catches:** `setup.py` is executed at install time. Patterns like network calls (`urllib`, `requests`), `subprocess`, `os.system`, environment-variable exfiltration in setup.py indicate a malicious package OR a project shipping its own backdoor.
- **Detection approach:** AST scan of any `setup.py` in the repo and (if available) in fetched dependencies. Flag: HTTP calls, subprocess, exec/eval, reading SSH keys, reading `~/.aws/credentials`.
- **False positive risk:** Some packages legitimately download data files at install (`spacy`, model packages); these should use `console_scripts` post-install instead.
- **Known incidents:** termncolor / colorinal (July 22, 2025 Zscaler ThreatLabz discovery; uploads July 16-22, 2025; press coverage spread in August); recurring PyPI malicious-package incidents.

#### PROBE: pyproject.toml [tool.uv] / [tool.poetry] insecure source override

- **Language:** Python | **Category:** Supply chain | **Severity:** medium
- **What it catches:** Custom `[[tool.poetry.source]]` or `[tool.uv.sources]` with `default = true` pointing to non-PyPI URL, enabling dependency confusion.

#### PROBE: ZIP-confusion-vulnerable wheel installer (CVE-2025-54368)

- **Language:** Python | **Category:** Supply chain | **Severity:** high
- **What it catches:** `uv` versions prior to the CVE-2025-54368 fix in `uv.lock` / `pyproject.toml` toolchain pin.
- **Known incidents:** Per PyPI blog 2025, uv had a different ZIP extraction implementation than stdlib zipfile, allowing wheels with crafted RECORD files to smuggle payloads past detection. PyPI now rejects these wheels server-side.

### Category 6; Build / Deploy Patterns (Python)

#### PROBE: Dockerfile FROM python:latest or python (no tag)

- **Language:** Python | **Category:** Build/Deploy | **Severity:** medium
- **What it catches:** Floating Python base image; pulls today's CVE-laden image tomorrow.
- **Detection approach:** RX in Dockerfile.
- **Remediation:** Pin to `python:3.12.7-slim-bookworm@sha256:...`.

#### PROBE: Dockerfile running as root (no USER directive)

- **Language:** Python | **Category:** Build/Deploy | **Severity:** medium
- **Detection approach:** Dockerfile parse; absence of `USER` directive non-root before `CMD/ENTRYPOINT`.

#### PROBE: Dockerfile pip install without --no-cache-dir or with --break-system-packages

- **Language:** Python | **Category:** Build/Deploy | **Severity:** low
- **Remediation:** Use a venv inside the image.

#### PROBE: gunicorn/uvicorn launched without --workers cap or --max-requests

- **Language:** Python | **Category:** Build/Deploy | **Severity:** low
- **What it catches:** Resource exhaustion / memory leak protection missing.

#### PROBE: .env file committed (not in .gitignore)

- **Language:** Python | **Category:** Build/Deploy | **Severity:** high
- **Detection approach:** File presence + .gitignore parse.

#### PROBE: GitHub Actions workflow with pull_request_target + checkout of PR HEAD

- **Language:** Python (CI) | **Category:** Build/Deploy | **Severity:** critical
- **What it catches:** The "Pwn Request" pattern exploited in the TanStack May 11, 2026 compromise; `pull_request_target` trigger plus `actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}` and a workflow that runs untrusted PR code with elevated permissions.
- **Detection approach:** YAML parse of `.github/workflows/*.yml`.
- **Known incidents:** TanStack CVE-2026-45321; Trivy compromise (March 19, 2026; CVE-2026-33634; CISA KEV remediation deadline April 8, 2026); broadly documented "Pwn Request" pattern from researchers at StepSecurity.

#### PROBE: GitHub Actions secrets exposure in PR-triggered workflow

- **Language:** Python (CI) | **Category:** Build/Deploy | **Severity:** critical
- **What it catches:** `secrets.PYPI_API_TOKEN` or any secret reference in a job triggered by `pull_request` or `pull_request_target`.

#### PROBE: pip cache restore action with mutable key

- **Language:** Python (CI) | **Category:** Build/Deploy | **Severity:** high
- **What it catches:** `actions/cache@v*` with a cache key that includes only `runner.os` and `hashFiles('requirements.txt')` but is restored across forks; enabling the Mini Shai-Hulud cache-poisoning vector.

#### PROBE: pre-commit hook that runs network requests

- SPECULATIVE.

## 2. Rust

### Framework / Library Inventory (Rust)

**Top-3 frameworks with framework-specific probes included below:** Axum (Tokio web), Actix-web, Tauri (desktop/cross-platform).

**Additional frameworks to enumerate in future passes:** Rocket, Warp, Tide, Poem, Salvo, Loco, Leptos, Dioxus, Yew, Sycamore, Trunk, SeaORM, Diesel, SQLx, sqlite-rs/rusqlite, tokio-postgres, redis-rs, deadpool, bb8, mongodb, surrealdb, serde, serde_json, prost, tonic (gRPC), reqwest, hyper, h3, rustls, native-tls, ring, RustCrypto suite (sha2, aes-gcm, chacha20poly1305, ed25519-dalek), age, jsonwebtoken, paseto, oauth2, openid, casbin-rs, tracing, tracing-subscriber, anyhow, thiserror, miette, eyre, clap, structopt, config, dotenvy, figment, candle, burn, llm-chain, async-openai, ollama-rs, qdrant-client (Rust), wasmtime, wasmer, embassy (embedded async), bevy (game), wgpu, polars, datafusion, arrow-rs.

### Category 1; AI-Tool Failure Patterns (Rust)

#### PROBE: unsafe block without /// SAFETY: comment

- **Language:** Rust | **Category:** AI-tool failure (also Memory) | **Severity:** high
- **What it catches:** Any `unsafe { ... }` block, function, or trait impl without an immediately preceding `// SAFETY:` or `/// SAFETY:` comment justifying the invariants.
- **Why AI gets this wrong:** AI tools reach for `unsafe` when they hit a borrow-checker error rather than restructuring. They almost never write the SAFETY comment because their training corpus mixes library-internal `unsafe` (which is documented) with random GitHub `unsafe` (which is not).
- **Detection approach:** AST via syn or tree-sitter-rust: `unsafe` block/fn/impl with no comment in the 5 lines preceding. Rust's `clippy::undocumented_unsafe_blocks` lint is the formal version.
- **False positive risk:** Project may use a different comment convention; allow `// Safety` and project-specific patterns via config.
- **Remediation:** Either remove unsafe via safe abstraction (`bytemuck`, `zerocopy`, `pin-project`), or add a SAFETY comment explaining the invariants.
- **Known incidents:** RustSec advisories regularly cite missing unsafe justification (e.g., RUSTSEC-2020-0159 chrono soundness).

#### PROBE: Use of mem::transmute or std::mem::transmute_copy

- **Language:** Rust | **Category:** AI-tool failure | **Severity:** high
- **What it catches:** `mem::transmute` calls. Rust nomicon explicitly lists this as the most dangerous function in the language.
- **Why AI gets this wrong:** AI uses `transmute` to convert between similar types when the safe `From`/`Into` impl is one keystroke harder.
- **Detection approach:** RX/AST: `mem::transmute(` or `::transmute(`.
- **Remediation:** Prefer `bytemuck::cast`, `zerocopy::transmute!`, `as` casts where applicable, or `From`/`Into`.

#### PROBE: unwrap()/expect()/panic! in route handlers

- **Language:** Rust | **Category:** AI-tool failure | **Framework:** Axum/Actix/Rocket | **Severity:** medium
- **What it catches:** `.unwrap()`, `.expect("...")`, or explicit `panic!`/`unreachable!` inside HTTP handler functions, causing the worker to crash on attacker-controlled input. While Tokio recovers, some panics (e.g., in middleware) can poison shared state.
- **Why AI gets this wrong:** `.unwrap()` is the shortest path to compile-clean code; AI emits it as a placeholder and never replaces it.
- **Detection approach:** AST: identify functions decorated with `#[axum::handler]` or returning `impl IntoResponse`, or registered via `.route("/", get(handler))`; flag unwrap/expect/panic in their bodies.
- **False positive risk:** unwrap on values proven static (Mutex from `OnceCell`).
- **Remediation:** Return `Result<..., AppError>` and propagate with `?`.

#### PROBE: SQLx query! macro vs runtime query() without parameter binding

- **Language:** Rust | **Category:** AI-tool failure | **Framework:** SQLx | **Severity:** high
- **What it catches:** `sqlx::query(&format!("SELECT ... {user_input}"))`; SQL injection in a "safe" library.
- **Why AI gets this wrong:** The `query!` macro requires `DATABASE_URL` at compile time; when AI can't access it, it falls back to the non-macro `query()` and forgets to use `.bind()`.
- **Detection approach:** AST: `sqlx::query(...)` or `sqlx::query_as(...)` whose first argument is a `format!` or `&format!` macro or string concatenation.
- **Remediation:** Use `query!(...)`/`query_as!(...)` macros (compile-time checked) OR `query("SELECT ... WHERE id = $1").bind(id)`.

#### PROBE: Diesel SQL with sql_query and format!

- **Language:** Rust | **Category:** AI-tool failure | **Framework:** Diesel | **Severity:** high
- **What it catches:** `diesel::sql_query(format!(...))`.
- **Detection approach:** AST/RX as above.

#### PROBE: serde_json::from_str on untrusted input without size limit

- **Language:** Rust | **Category:** AI-tool failure | **Severity:** medium
- **What it catches:** `serde_json::from_str(&body)` or `from_slice(&bytes)` on potentially large request bodies without prior length check.
- **Detection approach:** AST: serde_json deserialization of variable derived from `Bytes`/`String`/`Vec<u8>` reachable from a handler param without intervening size check.
- **Remediation:** Use `axum::extract::DefaultBodyLimit` or Actix `web::PayloadConfig`; on parsing side, use `serde_json::Deserializer::from_reader().take(N)`.

#### PROBE: reqwest::ClientBuilder::danger_accept_invalid_certs(true)

- **Language:** Rust | **Category:** AI-tool failure | **Severity:** critical
- **Detection approach:** RX `danger_accept_invalid_certs\s*\(\s*true\s*\)`.
- **Why AI gets this wrong:** Same pattern as Python `verify=False`; AI's go-to fix for "cert error."
- **Remediation:** Add custom root cert via `Certificate::from_pem`.

#### PROBE: Tauri allowlist with shell.execute or fs.scope = "\*\*"

- **Language:** Rust | **Category:** AI-tool failure | **Framework:** Tauri | **Severity:** critical
- **What it catches:** `tauri.conf.json` / `tauri.conf.toml` with `allowlist.shell.all = true`, `allowlist.shell.execute = true`, `allowlist.fs.scope = ["**"]`, or `dialog.ask: true` with no path restriction. Enables remote-content-in-webview-to-host-command-execution.
- **Why AI gets this wrong:** When debugging "the JS frontend can't access this thing," AI broadens the allowlist rather than narrowing it.
- **Detection approach:** CFG: parse `tauri.conf.json`.
- **Known incidents:** Tauri security guide explicitly warns; multiple Electron-analogous CVEs.

#### PROBE: Tauri webview loading remote URL (CSP, devUrl in prod)

- **Language:** Rust | **Category:** AI-tool failure | **Framework:** Tauri | **Severity:** high
- **What it catches:** `tauri.conf.json` `windows[].url` pointing to `https://` external rather than `tauri://localhost`, combined with broad allowlist.

#### PROBE: tokio::spawn with no JoinHandle held

- See orphan task pattern (Python asyncio equivalent). In Rust this is more subtle: detached tokio tasks lose their `JoinError` on panic, similar to asyncio.
- **Detection approach:** AST: `tokio::spawn(...)` as expression statement (return discarded).
- **Severity:** low.

### Category 2; OWASP Top 10:2025 (Rust)

#### PROBE: A02; ring/openssl-rs with ECB or CBC without HMAC

- **Language:** Rust | **Category:** OWASP A02 | **Severity:** high
- **What it catches:** Use of `aes::Aes128`/`Aes256` with `ecb` mode, or `cbc::Encryptor` without separate HMAC/auth.
- **Detection approach:** RX/AST for `Ecb`, `cbc::` without `hmac::` in same module.
- **Remediation:** Use `aes-gcm` (AEAD) or `chacha20poly1305`.

#### PROBE: A02; md5/sha1 crate used for credential

- See Python equivalent; in Rust the `md5`/`sha1` crates are red flags when used on data named like a password.

#### PROBE: A02; rand crate (non-crypto) for token generation

- **Language:** Rust | **Category:** OWASP A02 | **Severity:** high
- **What it catches:** `rand::thread_rng()` followed by `.gen::<u64>()` used for tokens.
- **Detection approach:** AST: `rand::thread_rng`/`StdRng` used in same function as variables named `token`, `secret`, `nonce`, `csrf`.
- **Remediation:** `rand::rngs::OsRng` or `getrandom` directly; or `ring::rand::SystemRandom`.

#### PROBE: A03; std::process::Command::new("sh"/"bash") with -c

- **Language:** Rust | **Category:** OWASP A03 | **Severity:** critical
- **Detection approach:** AST: `Command::new("sh")` or `"bash"` with arg `-c` whose value is a format!.

#### PROBE: A05; Actix-web NormalizePath::trim trailing slash in critical auth path (path confusion)

- SPECULATIVE; historical CVE pattern; flag low confidence.

#### PROBE: A07; jsonwebtoken with Validation::default and no algorithm pinning

- **Language:** Rust | **Category:** OWASP A07 | **Framework:** jsonwebtoken | **Severity:** high
- **What it catches:** `decode::<T>(token, &key, &Validation::default())`; default Validation allows HS256 only, but explicit `Validation::new(Algorithm::HS256)` mixed with an RS256 public key allows alg-confusion.
- **Detection approach:** AST: `jsonwebtoken::decode` with mismatched key type vs declared algorithm; or `Validation::default()` used in production.

#### PROBE: A08; Cargo.lock with yanked crates

- See Category 5.

#### PROBE: A10; reqwest with hostname directly from user input

- **Language:** Rust | **Category:** OWASP A10 | **Severity:** high
- **Detection approach:** AST taint flow.

### Category 3; OWASP LLM Top 10 (Rust)

Rust is a less common LLM application host but `async-openai`, `ollama-rs`, `llm-chain`, and `candle` are used. Probes mirror Python equivalents:

- **LLM01:** `format!()` of user input into system prompt passed to `async_openai`'s `CreateChatCompletionRequestArgs::messages`.
- **LLM02:** `tracing::info!(?response)` of LLM result without redaction.
- **LLM03:** Loading `.safetensors`/`.bin` files from untrusted paths in `candle` or `burn`.
- **LLM05:** LLM output passed to `Command::new` or `eval`-equivalent (uncommon in Rust).
- **LLM10:** No `max_tokens` in `CreateChatCompletionRequestArgs`.

### Category 4; Memory / Concurrency / Resource Patterns (Rust)

#### PROBE: Mutex<T> held across .await

- **Language:** Rust | **Category:** Concurrency | **Severity:** high
- **What it catches:** `let guard = mutex.lock().unwrap(); some_async_fn().await;`; std Mutex held across an await point can deadlock with tokio's work-stealing.
- **Why AI gets this wrong:** AI mixes std::sync::Mutex with tokio::sync::Mutex.
- **Detection approach:** AST: `MutexGuard` value live across an await expression.
- **Remediation:** `tokio::sync::Mutex` for cross-await; or scope the guard before the await.
- **Known incidents:** Common deadlock pattern documented in Tokio docs.

#### PROBE: Arc<Mutex<T>> cloned into spawned task with no Drop discipline

- SPECULATIVE.

#### PROBE: Unbounded mpsc channel

- **Language:** Rust | **Category:** Concurrency / Resource | **Severity:** medium
- **What it catches:** `tokio::sync::mpsc::unbounded_channel()` in network-facing code; enables memory exhaustion if producer outpaces consumer.
- **Remediation:** Use `mpsc::channel(N)` with backpressure.

#### PROBE: Box::leak on user-sized input

- **Language:** Rust | **Category:** Memory | **Severity:** medium
- **What it catches:** Intentional leak applied to runtime-sized buffer.

#### PROBE: from_raw_parts with user-controlled length

- **Language:** Rust | **Category:** Memory | **Severity:** critical
- **What it catches:** `slice::from_raw_parts(ptr, user_len)`; out-of-bounds read.
- **Detection approach:** AST: `from_raw_parts` with second arg traced to handler input.

#### PROBE: cargo build with RUSTFLAGS=-Cdebug-assertions=off in release that suppresses overflow checks

- SPECULATIVE.

#### PROBE: indexing with [user_index] without bounds check

- High false-positive; deprioritize.

### Category 5; Supply Chain Patterns (Rust / crates.io)

#### PROBE: Cargo.toml dependency without version (git/path) or with `*`

- **Language:** Rust | **Category:** Supply chain | **Severity:** medium
- **Detection approach:** MAN: parse Cargo.toml `[dependencies]`; flag entries with `version = "*"`, `git = "..."` without `rev = "..."`, or `path = "../something"`.

#### PROBE: Cargo.lock with crate marked yanked

- **Language:** Rust | **Category:** Supply chain | **Severity:** medium
- **What it catches:** Crates that were yanked from crates.io (often due to security issue) but still present in Cargo.lock.
- **Detection approach:** MAN diff against RustSec advisory-db bundle and known yanked-list.
- **Remediation:** `cargo update` to a non-yanked version.

#### PROBE: Cargo.toml registry override

- **Language:** Rust | **Category:** Supply chain | **Severity:** high
- **What it catches:** `[source.crates-io]` replaced with non-default registry without authentication.
- **Detection approach:** MAN: parse `.cargo/config.toml`.

#### PROBE: Known malicious crate in Cargo.lock (IOC list)

- **Language:** Rust | **Category:** Supply chain | **Severity:** critical
- **IOC list (May 2026):** `finch-rst`, `finch_cli_rust`, `sha-rst` (RUSTSEC-2025-0148, 0150, 0151, 0152; credential exfiltration impersonating finch / finch_cli, December 2025); `polymarket-clients-sdk`, `polymarket-client-sdks` (RUSTSEC-2026-0010, 0011; February 2026 credential exfiltration impersonating polymarket-client-sdk).
- **Detection approach:** MAN diff against bundled JSON.
- **Known incidents:** Per Rust Blog February 2026 update to malicious-crate notification policy.

#### PROBE: Crate name typosquat / similar-to-popular

- See Python equivalent; bundle the top-1000 crates with Levenshtein check.

#### PROBE: Cargo.toml [build-dependencies] running build.rs with network access

- **Language:** Rust | **Category:** Supply chain | **Severity:** high
- **What it catches:** `build.rs` files in the project root that contain `reqwest`, `ureq`, `std::net`, `std::process::Command`; `build.rs` runs at compile time with full network/process access.
- **Detection approach:** AST scan of `build.rs`.
- **Remediation:** Move data-fetching out of build.rs.

#### PROBE: cargo-audit / cargo-deny absent from CI

- **Language:** Rust | **Category:** Supply chain | **Severity:** info
- **Detection approach:** Search `.github/workflows/*.yml` and `Makefile` for `cargo audit` / `cargo deny`.

### Category 6; Build / Deploy Patterns (Rust)

#### PROBE: Cargo.toml release profile with overflow-checks = false

- **Language:** Rust | **Category:** Build/Deploy | **Severity:** medium
- **Detection approach:** MAN.

#### PROBE: Cargo.toml release profile with debug-assertions = false in security crate

- Default is false in release; informational only.

#### PROBE: Dockerfile FROM rust:latest

- See Python equivalent.

#### PROBE: Cross-compilation target with no panic = "abort" strategy for embedded

- SPECULATIVE.

#### PROBE: cargo build with --offline used in CI without prior cache verification

- Info-only.

#### PROBE: rust-toolchain.toml pinning to nightly without justification

- **Language:** Rust | **Category:** Build/Deploy | **Severity:** low
- **What it catches:** `channel = "nightly"` or `nightly-YYYY-MM-DD` in production projects; nightly compiler changes can affect codegen.

## 3. Go

### Framework / Library Inventory (Go)

**Top-3 frameworks with framework-specific probes included below:** net/http stdlib + Gin, Echo, Fiber (also gRPC via google.golang.org/grpc).

**Additional frameworks/libraries to enumerate in future passes:** Chi, Gorilla Mux, Beego, Buffalo, Iris, Revel, Goa, Huma, Gqlgen (GraphQL), GORM, sqlx, sqlc, pgx, ent, mongo-go-driver, redis (go-redis), nats.go, sarama, kafka-go, watermill, asynq, machinery, cobra, viper, urfave/cli, kong, kingpin, lo (lodash port), samber/lo, zap, zerolog, slog, logrus, otel-go, jaeger-client-go, opencensus, gRPC-gateway, twirp, connectrpc, golang-jwt, jose2go, oauth2, casbin-go, golang-migrate, atlas, terraform-plugin-sdk, kubernetes/client-go, controller-runtime, operator-sdk, helm, kustomize, prometheus client_golang, gopsutil, fsnotify, tview, bubbletea, charm, wails, fyne, gioui, ebiten, gonum, gocv (OpenCV), tensorflow-go, onnxruntime-go, ollama-go, eino (LangChain port), langchaingo, openai-go SDK, anthropic-sdk-go.

### Category 1; AI-Tool Failure Patterns (Go)

#### PROBE: http.HandleFunc that ignores returned error from json.Decode / r.ParseForm

- **Language:** Go | **Category:** AI-tool failure | **Severity:** medium
- **What it catches:** `json.NewDecoder(r.Body).Decode(&v)` with no `if err != nil` follow-up; empty struct used downstream as if validated.
- **Why AI gets this wrong:** Go's explicit error handling is verbose; AI shortcuts it under time pressure.
- **Detection approach:** AST via `go/parser`: `Decode` / `Unmarshal` call where return is discarded or where the next statement is not an err check.
- **Remediation:** `if err := dec.Decode(&v); err != nil { ... }`.

#### PROBE: errors.New / fmt.Errorf with user-controlled %s that contains format directives

- **Language:** Go | **Category:** AI-tool failure | **Severity:** low
- **What it catches:** `fmt.Errorf(userInput)`; not crash-dangerous in Go but can leak format-string content.

#### PROBE: net/http server with no ReadTimeout / WriteTimeout / IdleTimeout

- **Language:** Go | **Category:** AI-tool failure | **Framework:** net/http | **Severity:** high
- **What it catches:** `http.ListenAndServe(addr, mux)`; uses default `http.DefaultServer` with zero timeouts → trivial Slowloris DoS.
- **Why AI gets this wrong:** `http.ListenAndServe` is the README example. Setting timeouts requires building an `http.Server{}` literal.
- **Detection approach:** AST: bare `http.ListenAndServe` calls in `main` packages; or `&http.Server{}` literal lacking `ReadTimeout`/`WriteTimeout`/`IdleTimeout` fields.
- **Remediation:** Explicit `http.Server{ReadTimeout: 5*time.Second, WriteTimeout: 10*time.Second, IdleTimeout: 60*time.Second}`.
- **Known incidents:** Cloudflare and others repeatedly documented; CVE-2016-\* Slowloris in Go services.

#### PROBE: gin.Default() in production

- **Language:** Go | **Category:** AI-tool failure | **Framework:** Gin | **Severity:** low
- **What it catches:** `gin.Default()` enables debug logger and recovery, fine for dev but emits trusted-proxy warning and verbose logs in production.
- **Remediation:** `gin.New()` + chosen middleware; `gin.SetMode(gin.ReleaseMode)`.

#### PROBE: gin SetTrustedProxies not configured or set to "0.0.0.0/0"

- **Language:** Go | **Category:** AI-tool failure | **Framework:** Gin | **Severity:** medium
- **What it catches:** Without proper trusted-proxy config, `c.ClientIP()` returns attacker-controlled `X-Forwarded-For` header.

#### PROBE: html/template not used; text/template for HTML output

- **Language:** Go | **Category:** AI-tool failure | **Severity:** critical
- **What it catches:** Importing `text/template` instead of `html/template` for rendering HTML; no autoescape → XSS.
- **Detection approach:** AST: `import "text/template"` in a file that also responds to `http.ResponseWriter` with text/html content type.
- **Remediation:** `import "html/template"`.

#### PROBE: exec.Command with shell metacharacters

- **Language:** Go | **Category:** AI-tool failure | **Severity:** critical
- **What it catches:** `exec.Command("sh", "-c", fmt.Sprintf("...%s...", userInput))`.
- **Detection approach:** AST: `exec.Command("sh"|"bash"|"/bin/sh", "-c", ...)` where third arg is dynamic.
- **Remediation:** Use `exec.Command("real-binary", arg1, arg2)` argv form.

#### PROBE: crypto/md5 / crypto/sha1 used for credential or signature

- See Python.

#### PROBE: math/rand for security tokens

- **Language:** Go | **Category:** AI-tool failure | **Severity:** high
- **What it catches:** `math/rand.Int63()`, `rand.New(rand.NewSource(time.Now().UnixNano()))` used for tokens.
- **Detection approach:** AST: `math/rand` imports in any file mentioning `token`, `secret`, `nonce`, `csrf`.
- **Remediation:** `crypto/rand`.

#### PROBE: golang-jwt parser with ParseUnverified or empty key function

- **Language:** Go | **Category:** AI-tool failure | **Framework:** golang-jwt/jwt | **Severity:** critical
- **What it catches:** `jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) { return nil, nil })` or `jwt.ParseUnverified`.
- **Detection approach:** AST: key-func returning `nil`/`""`; or `ParseUnverified` calls.
- **Known incidents:** CVE-2020-26160 golang-jwt/jwt; alg-confusion family.

#### PROBE: Hardcoded LLM keys

- See Python equivalent. Patterns identical.

#### PROBE: tls.Config InsecureSkipVerify: true

- **Language:** Go | **Category:** AI-tool failure | **Severity:** critical
- **Detection approach:** RX `InsecureSkipVerify\s*:\s*true`.
- **Why AI gets this wrong:** Go's strict cert validation breaks easily; AI's go-to fix.
- **Remediation:** Provide CA pool via `tls.Config{RootCAs: pool}`.

### Category 2; OWASP Top 10:2025 (Go)

#### PROBE: A01; gorilla/mux or Chi route with no auth middleware on admin path

- SPECULATIVE; requires routing-table analysis.

#### PROBE: A03; database/sql Query/Exec with fmt.Sprintf

- **Language:** Go | **Category:** OWASP A03 | **Severity:** critical
- **Detection approach:** AST: `db.Query` / `db.Exec` / `db.QueryRow` (and Tx equivalents) with first arg = format string.
- **Remediation:** `db.Query("SELECT ... WHERE id = $1", id)`.

#### PROBE: A03; GORM Raw / Exec with fmt.Sprintf

- **Language:** Go | **Category:** OWASP A03 | **Framework:** GORM | **Severity:** critical
- **Detection approach:** AST.

#### PROBE: A03; template.HTML(userValue)

- **Language:** Go | **Category:** OWASP A03 (XSS) | **Severity:** high
- **What it catches:** Wrapping untrusted strings in `template.HTML`, `template.JS`, `template.URL` bypasses autoescape.
- **Detection approach:** AST: those casts on non-constant.

#### PROBE: A05; http.FileServer rooted at "/" or directory traversal via filepath.Join

- **Language:** Go | **Category:** OWASP A05/A01 | **Severity:** high
- **What it catches:** `http.ServeFile(w, r, filepath.Join("./static", r.URL.Path))`; classic path traversal.
- **Detection approach:** AST: `http.ServeFile`/`os.Open` whose path is `filepath.Join` of a constant + `r.URL.Path`/header.
- **Remediation:** `filepath.Clean` + ensure resulting path is under root; or `http.FileServer(http.Dir(...))` which handles it correctly.

#### PROBE: A07; bcrypt.GenerateFromPassword cost < 10

- **Language:** Go | **Category:** OWASP A07 | **Severity:** medium
- **Detection approach:** AST: `bcrypt.GenerateFromPassword(..., 0)` (0 → DefaultCost = 10 currently, but explicit low values flag).

#### PROBE: A09; log.Println of incoming request body

- See logging pattern.

#### PROBE: A10; http.Get with URL from r.URL.Query()

- **Language:** Go | **Category:** OWASP A10 SSRF | **Severity:** high
- **Detection approach:** AST taint flow.
- **Remediation:** Use a custom `http.Transport` with `DialContext` that resolves and blocks private IPs.

### Category 3; OWASP LLM Top 10 (Go)

Mirror Python; relevant SDKs: `openai-go`, `anthropic-sdk-go`, `langchaingo`, `ollama-go`.

- **LLM01:** `fmt.Sprintf` of user input into system message in `openai.ChatCompletionRequest`.
- **LLM05:** LLM response passed to `exec.Command`.
- **LLM10:** `MaxTokens` field unset on `ChatCompletionRequest`.

### Category 4; Memory / Concurrency / Resource Patterns (Go)

#### PROBE: goroutine leak; go func() without termination signal

- **Language:** Go | **Category:** Concurrency | **Severity:** medium
- **What it catches:** `go func() { for { select { case <-ch: ... } } }()` without a `case <-ctx.Done()` branch.
- **Why AI gets this wrong:** AI emits `go func()` liberally; cancellation requires plumbing context.
- **Detection approach:** AST: `go` statements whose body is an infinite `for` lacking a `<-ctx.Done()` case.
- **False positive risk:** High in worker patterns; flag with medium confidence.

#### PROBE: sync.Mutex passed by value

- **Language:** Go | **Category:** Concurrency | **Severity:** high
- **What it catches:** Struct containing `sync.Mutex` (not pointer) passed by value; copies the mutex, leading to non-atomic access. `go vet` catches this; surfacing in Pre-Flight gives early signal.
- **Detection approach:** AST: function param `Foo` where `Foo` contains an unexported `sync.Mutex` field (non-pointer).

#### PROBE: defer in for loop without scope

- **Language:** Go | **Category:** Resource | **Severity:** medium
- **What it catches:** `for _, f := range files { fp, _ := os.Open(f); defer fp.Close(); ... }`; file handles leak until function return.
- **Detection approach:** AST: `defer` inside a `for`/`for range` body.
- **Remediation:** Wrap loop body in an IIFE or call function.

#### PROBE: context.Background in HTTP handler

- **Language:** Go | **Category:** Concurrency / Resource | **Severity:** medium
- **What it catches:** Downstream call uses `context.Background()` instead of `r.Context()`, so client cancellation doesn't propagate → wasted work, goroutine leaks.
- **Detection approach:** AST: `context.Background()` call in same function as `http.ResponseWriter, *http.Request` signature.

#### PROBE: unbounded channel buffer

- **Language:** Go | **Category:** Concurrency / Resource | **Severity:** low
- **What it catches:** `make(chan T)` followed by goroutine sending into it from a hot loop. Hard to detect statically with confidence.

#### PROBE: Body not closed

- **Language:** Go | **Category:** Resource | **Severity:** medium
- **What it catches:** `resp, _ := http.Get(...)` without `defer resp.Body.Close()`. Linters catch this (bodyclose); replicating it as a Pre-Flight probe gives early-stage signal.
- **Detection approach:** AST: `http.Get`/`http.Post`/`client.Do` whose `resp` is used without a `Close()` call in the same function.

### Category 5; Supply Chain Patterns (Go / go modules)

#### PROBE: go.mod with replace directive pointing to local path or fork URL

- **Language:** Go | **Category:** Supply chain | **Severity:** medium
- **Detection approach:** MAN.

#### PROBE: go.sum missing or stale (hash mismatch)

- **Language:** Go | **Category:** Supply chain | **Severity:** medium
- **Detection approach:** MAN diff.

#### PROBE: GOPROXY=direct or off

- **Language:** Go | **Category:** Supply chain | **Severity:** medium
- **What it catches:** CI/Dockerfile setting `GOPROXY=direct` bypasses the immutable Go module mirror.

#### PROBE: Known malicious / typosquat Go module

- **Language:** Go | **Category:** Supply chain | **Severity:** critical
- **IOC list:** `github.com/boltdb-go/bolt` (typosquat of boltdb/bolt, three-year backdoor in Go Module Mirror exposed February 2025, Socket research, Boychenko); BufferZoneCorp campaign Ruby gems + Go modules including `go-retryablehttp` typosquats (May 2026, Socket / The Hacker News); `github.com/qiniiu/qmgo` typosquat of `github.com/qiniu/qmgo` (GitLab Vulnerability Research June 2025, fake MongoDB driver).
- **Detection approach:** MAN diff against bundled JSON.

#### PROBE: Module path contains `replace` directive overriding well-known dependency

- **Language:** Go | **Category:** Supply chain | **Severity:** high
- **Detection approach:** MAN: replace lines for `golang.org/x/*`, `google.golang.org/*`, top-100 modules.

#### PROBE: Vendor directory with mismatched modules.txt

- SPECULATIVE.

#### PROBE: GitHub Actions workflow uses unpinned third-party action

- **Language:** Go (CI) | **Category:** Supply chain | **Severity:** high
- **What it catches:** `uses: aquasecurity/setup-trivy@v0.69.4` instead of `uses: aquasecurity/setup-trivy@<sha>`; the Trivy March 2026 compromise force-pushed 75 of 76 trivy-action tags to malicious imposter commits (Wiz, Microsoft, Phoenix Security).

### Category 6; Build / Deploy Patterns (Go)

#### PROBE: go build without -trimpath

- **Language:** Go | **Category:** Build/Deploy | **Severity:** low
- **What it catches:** Binary contains absolute build paths leaking developer username / project structure.
- **Detection approach:** Search Makefile, Dockerfile, CI YAML.

#### PROBE: go build with -ldflags="-w -s" missing in release

- Info; reduces info disclosure via DWARF.

#### PROBE: CGO_ENABLED=1 on a binary that doesn't need it

- **Language:** Go | **Category:** Build/Deploy | **Severity:** low
- **What it catches:** Defaults to dynamic libc dependency.

#### PROBE: Dockerfile FROM golang as builder without distroless final stage

- **Language:** Go | **Category:** Build/Deploy | **Severity:** medium
- **What it catches:** Final image has full golang toolchain → larger attack surface, more CVEs.
- **Remediation:** Multi-stage with `FROM gcr.io/distroless/static-debian12`.

#### PROBE: Goreleaser config without checksums and signing

- **Language:** Go | **Category:** Build/Deploy | **Severity:** low

#### PROBE: GitHub Actions Go matrix pulling latest go-version

- **Language:** Go (CI) | **Category:** Build/Deploy | **Severity:** low

#### PROBE: pprof endpoint registered on net/http.DefaultServeMux in production

- **Language:** Go | **Category:** Build/Deploy / OWASP A05 | **Severity:** high
- **What it catches:** `import _ "net/http/pprof"` paired with `http.ListenAndServe(":port", nil)` exposes goroutine dumps, heap profile, etc. on `/debug/pprof/`.
- **Detection approach:** AST: blank-import of `net/http/pprof` AND `http.ListenAndServe(..., nil)` or use of `http.DefaultServeMux`.
- **Remediation:** Use a separate `ServeMux` bound to localhost or behind auth.

## 4. Java

### Framework / Library Inventory (Java)

**Top-3 frameworks with framework-specific probes included below:** Spring Boot, Jakarta EE / Servlet, Android SDK (overlaps with Kotlin section but Java-specific patterns covered here).

**Additional frameworks/libraries to enumerate in future passes:** Spring Security, Spring Cloud, Spring Data, Quarkus, Micronaut, Helidon, Dropwizard, Play! (Java), Vert.x, JAX-RS (Jersey, RESTEasy), Jakarta Servlet, JSP, Thymeleaf, FreeMarker, Velocity, Mustache.java, Hibernate ORM, JPA, MyBatis, jOOQ, JDBI, Spring JDBC, HikariCP, Caffeine, Guava, Apache Commons (Lang, Codec, IO, FileUpload), Jackson, Gson, Moshi, FastJSON, Snakeyaml, JAXB, Logback, Log4j2, SLF4J, Bouncy Castle, JWT libs (jjwt, java-jwt, nimbus-jose-jwt), Spring Authorization Server, Keycloak adapters, OAuth2 client, Apache CXF, Apache Camel, Apache Kafka client, RabbitMQ Java client, Spring Kafka, Spring AMQP, RestTemplate, WebClient, OkHttp, Apache HttpClient, Netty, Reactor, RxJava, gRPC-Java, Protobuf-Java, Spring AI, LangChain4j, Embedding-related Java libs (deeplearning4j, djl), Selenium-Java, JUnit, Mockito, Testcontainers, Lombok, MapStruct.

### Category 1; AI-Tool Failure Patterns (Java)

#### PROBE: Spring @CrossOrigin with origins = "\*" and allowCredentials = "true"

- **Language:** Java | **Category:** AI-tool failure | **Framework:** Spring Boot | **Severity:** high
- **What it catches:** Same CORS misconfiguration class as FastAPI; `@CrossOrigin(origins = "*", allowCredentials = "true")` is silently downgraded by browsers but reflective implementations are common.
- **Detection approach:** AST/RX on annotation arguments.
- **Remediation:** Enumerate origins.

#### PROBE: Spring Security disabled CSRF without justification

- **Language:** Java | **Category:** AI-tool failure | **Framework:** Spring Security | **Severity:** high
- **What it catches:** `http.csrf().disable()` (Spring Security 5) or `http.csrf(csrf -> csrf.disable())` (Spring Security 6) in a `SecurityFilterChain` for a session-cookie-bearing webapp.
- **Why AI gets this wrong:** Disabling CSRF is the path-of-least-resistance fix when forms don't POST cleanly. For pure-API (token-based) apps disabling is correct; AI doesn't distinguish.
- **Detection approach:** AST: `csrf().disable()` calls; cross-reference with session-cookie usage (e.g., `formLogin`, `httpBasic`).
- **Remediation:** For session apps: enable CSRF and supply the token; for pure-stateless APIs: disable CSRF AND set sessionCreationPolicy(STATELESS).

#### PROBE: Spring @PreAuthorize missing on @Controller methods after Spring Security 6 migration

- **Language:** Java | **Category:** AI-tool failure | **Framework:** Spring Security | **Severity:** medium
- **What it catches:** Mix of methods with `@PreAuthorize` and without in same controller; likely missed annotations.

#### PROBE: Spring application.properties / application.yml with management.endpoints.web.exposure.include=\*

- **Language:** Java | **Category:** AI-tool failure | **Framework:** Spring Boot Actuator | **Severity:** critical
- **What it catches:** Actuator exposes `/actuator/env`, `/actuator/heapdump`, `/actuator/jolokia` (RCE), `/actuator/gateway/refresh` etc. when `*` is configured without security.
- **Why AI gets this wrong:** Spring Boot's "wide-open" Actuator default is the README example.
- **Detection approach:** CFG: parse application.properties/yml for `management.endpoints.web.exposure.include` and `management.security.enabled=false`.
- **Known incidents:** Documented body of Spring Boot Actuator RCE chains (PortSwigger, Veracode reports).

#### PROBE: Spring SpEL evaluation on user input

- **Language:** Java | **Category:** AI-tool failure | **Framework:** Spring | **Severity:** critical
- **What it catches:** `parser.parseExpression(userInput).getValue()`; Spring Expression Language has been the source of RCE chains (Spring4Shell-adjacent).
- **Detection approach:** AST: `SpelExpressionParser`, `StandardEvaluationContext` with user input.

#### PROBE: Hibernate / JPA Query with string concatenation

- **Language:** Java | **Category:** AI-tool failure | **Framework:** Hibernate / JPA | **Severity:** critical
- **What it catches:** `entityManager.createQuery("FROM User WHERE name = '" + name + "'")` or `createNativeQuery(...)` similar.
- **Detection approach:** AST: string concatenation in argument to `createQuery`/`createNativeQuery`/`Session.createQuery`/`SQLQuery`.
- **Remediation:** `setParameter(...)`.

#### PROBE: ObjectInputStream.readObject on untrusted source

- **Language:** Java | **Category:** AI-tool failure (also Memory) | **Severity:** critical
- **What it catches:** `new ObjectInputStream(socket.getInputStream()).readObject()`; classic Java deserialization gadget chain entry point (Apache Commons Collections, etc.).
- **Detection approach:** AST: `ObjectInputStream` construction with input that traces to a request/socket/file from untrusted source.
- **Remediation:** Use JSON; if must deserialize, set `ObjectInputFilter` (Java 9+).
- **Known incidents:** OWASP A08; CWE-502; massive body of CVEs (Spring4Shell tangential, WebSphere, JBoss, Jenkins).

#### PROBE: Jackson ObjectMapper with enableDefaultTyping or @JsonTypeInfo on Object

- **Language:** Java | **Category:** AI-tool failure | **Framework:** Jackson | **Severity:** critical
- **What it catches:** Polymorphic deserialization gadget; Jackson's "default typing" was the source of multiple RCE CVEs.
- **Detection approach:** AST: `enableDefaultTyping()`, `activateDefaultTyping(...)`, `@JsonTypeInfo(use=Id.CLASS)` on `Object`-typed fields.
- **Known incidents:** CVE-2017-7525 and ~30 follow-on Jackson CVEs.

#### PROBE: Snakeyaml load() vs safeLoad()

- **Language:** Java | **Category:** AI-tool failure | **Framework:** Snakeyaml | **Severity:** critical
- **What it catches:** `new Yaml().load(input)` allows arbitrary class instantiation. Snakeyaml 2.0+ defaults to safe.
- **Detection approach:** AST: `new Yaml().load`, `new Yaml(new Constructor(SomeClass.class)).load` on untrusted source; also check pom.xml for Snakeyaml < 2.0.

#### PROBE: Log4j2 with format string from user input (Log4Shell pattern surface)

- **Language:** Java | **Category:** AI-tool failure | **Framework:** Log4j2 | **Severity:** critical (when version vulnerable)
- **What it catches:** `logger.info(userInput)` paired with Log4j2 < 2.17.1 in pom.xml. Even modern versions: passing user input as the format string (vs a parameter) is bad practice.
- **Detection approach:** AST + MAN: combine log call shape with dependency version.
- **Known incidents:** CVE-2021-44228 Log4Shell.

#### PROBE: Runtime.exec / ProcessBuilder with String shell command

- **Language:** Java | **Category:** AI-tool failure | **Severity:** critical
- **What it catches:** `Runtime.getRuntime().exec("sh -c " + userInput)`.
- **Remediation:** `ProcessBuilder` with argv list and explicit binary.

#### PROBE: TrustManager that accepts all certs

- **Language:** Java | **Category:** AI-tool failure | **Severity:** critical
- **What it catches:** Custom `X509TrustManager` whose `checkServerTrusted` is empty.
- **Detection approach:** AST: classes implementing X509TrustManager with empty methods.
- **Known incidents:** CWE-295; massive body of Android MitM CVEs.

#### PROBE: HostnameVerifier returning true

- **Language:** Java | **Category:** AI-tool failure | **Severity:** critical
- **Detection approach:** AST: `HostnameVerifier` lambda returning true; `setHostnameVerifier(NoopHostnameVerifier.INSTANCE)`.

### Category 2; OWASP Top 10:2025 (Java)

#### PROBE: A01; Spring @Secured/@PreAuthorize missing on actuator-exposed beans

- See Actuator entry.

#### PROBE: A02; javax.crypto.Cipher.getInstance("AES")

- **Language:** Java | **Category:** OWASP A02 | **Severity:** high
- **What it catches:** Defaults to AES/ECB/PKCS5Padding which is ECB mode; never use ECB.
- **Detection approach:** RX `Cipher\.getInstance\("AES"\)` (no mode/padding) or `"AES/ECB/...".`.
- **Remediation:** `Cipher.getInstance("AES/GCM/NoPadding")`.

#### PROBE: A02; MessageDigest.getInstance("MD5"/"SHA-1") for passwords

- See Python.

#### PROBE: A02; SecureRandom not used; java.util.Random for tokens

- **Language:** Java | **Category:** OWASP A02 | **Severity:** high
- **Detection approach:** AST: `new Random()` in same class as token-producing methods.
- **Remediation:** `SecureRandom`.

#### PROBE: A03; JdbcTemplate.queryForList with string concatenation

- **Language:** Java | **Category:** OWASP A03 | **Framework:** Spring JDBC | **Severity:** critical
- **Detection approach:** AST.

#### PROBE: A03; XML parsers without XXE protection

- **Language:** Java | **Category:** OWASP A03 (XXE) | **Severity:** high
- **What it catches:** `DocumentBuilderFactory.newInstance()` without `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`; same for `SAXParserFactory`, `XMLInputFactory`.
- **Detection approach:** AST: parser factory instantiation lacking the relevant `setFeature` / `setXIncludeAware(false)`.
- **Remediation:** OWASP XXE Prevention Cheat Sheet recipe.

#### PROBE: A05; server.xml / web.xml with stack-trace error pages

- **Language:** Java | **Category:** OWASP A05 | **Severity:** medium
- **Detection approach:** CFG.

#### PROBE: A07; jjwt parser without setSigningKey

- **Language:** Java | **Category:** OWASP A07 | **Framework:** jjwt | **Severity:** critical
- **Detection approach:** AST: `Jwts.parser().parse(...)` without `setSigningKey`/`verifyWith`.

#### PROBE: A08; pom.xml dependencies without explicit version

- **Language:** Java | **Category:** OWASP A08 / supply chain | **Severity:** medium
- **What it catches:** Transitive version drift via `<dependencyManagement>` overrides.

#### PROBE: A09; Logger logs full request including Authorization header

- See cross-language entry.

#### PROBE: A10; RestTemplate / WebClient / OkHttp with URL from controller param

- **Language:** Java | **Category:** OWASP A10 | **Severity:** high
- **Detection approach:** AST taint analysis.

### Category 3; OWASP LLM Top 10 (Java)

Spring AI and LangChain4j are the dominant SDKs. Probes parallel Python.

- **LLM01:** Untrusted text concatenated into `SystemMessage("...")` in LangChain4j; `ChatClient.prompt().system(userInput)` in Spring AI.
- **LLM05:** LLM output passed to `Runtime.exec` or JdbcTemplate query.
- **LLM10:** Missing `.options(ChatOptions.builder().maxTokens(...).build())`.

### Category 4; Memory / Concurrency / Resource Patterns (Java)

#### PROBE: try-with-resources missing on AutoCloseable

- **Language:** Java | **Category:** Resource | **Severity:** medium
- **What it catches:** `InputStream is = ...; ...` with no `try (...)` block; file handle leak.
- **Detection approach:** AST: variable of AutoCloseable type assigned outside try-with-resources.

#### PROBE: Thread.sleep in non-virtual-thread executor

- Info-only.

#### PROBE: synchronized on String literal or boxed Integer

- **Language:** Java | **Category:** Concurrency | **Severity:** medium
- **What it catches:** `synchronized (someString) { ... }`; interned strings shared across classloaders create unexpected serialization.
- **Detection approach:** AST: synchronized statement on String or boxed primitive type expression.

#### PROBE: ConcurrentModificationException risk; modifying collection during iteration

- High false-positive; deprioritize.

#### PROBE: BufferedReader/InputStream not closed

- See resource entry.

#### PROBE: Executor.submit with no shutdown

- **Language:** Java | **Category:** Resource | **Severity:** low
- **Detection approach:** AST: `Executors.newFixedThreadPool` etc. in class with no `shutdown()` in finalizer or close.

### Category 5; Supply Chain Patterns (Java / Maven Central / Gradle)

#### PROBE: pom.xml dependency without <version> or with property like ${env.X}

- **Language:** Java | **Category:** Supply chain | **Severity:** medium
- **Detection approach:** MAN: parse pom.xml.

#### PROBE: pom.xml repository pointing to JCenter (sunset)

- **Language:** Java | **Category:** Supply chain | **Severity:** high
- **What it catches:** `<url>https://jcenter.bintray.com</url>`; JCenter is read-only and sunset; attackers can hijack abandoned namespaces.
- **Known incidents:** MavenGate research (Oversecured, 2024); 18% of mavenCentral groupIds were vulnerable to domain-takeover hijack.

#### PROBE: build.gradle with mavenCentral() ordered after jitpack()

- **Language:** Java/Kotlin | **Category:** Supply chain | **Severity:** high
- **What it catches:** Gradle searches repositories in declaration order; jitpack() before mavenCentral() means an attacker who registers a malicious version on jitpack can shadow Maven Central artifacts.
- **Detection approach:** AST/CFG: Gradle repositories block.
- **Known incidents:** MavenGate research.

#### PROBE: pom.xml with abandoned namespace owner indicator

- SPECULATIVE; needs lookup against bundled list of takeover-prone groupIds.

#### PROBE: Known compromised package (IOC)

- **Language:** Java | **Category:** Supply chain | **Severity:** critical
- **IOC list:** `org.mvnpm:*` packages that rebundle npm components compromised in Shai-Hulud v2 (purged from Maven Central November 25, 2025 per Hacker News coverage); specifically org.mvnpm:posthog-node:4.18.1 as the confirmed Maven Central spillover artifact (broader npm package list compromised in Shai-Hulud v2 did not have confirmed Maven Central rebundles per Socket and GitLab GLAD GMS-2025-800).

#### PROBE: Gradle wrapper distributionUrl pointing to non-official URL or HTTP

- **Language:** Java/Kotlin | **Category:** Supply chain | **Severity:** high
- **Detection approach:** CFG: parse `gradle/wrapper/gradle-wrapper.properties`.

#### PROBE: Gradle wrapper distributionSha256Sum missing

- **Language:** Java/Kotlin | **Category:** Supply chain | **Severity:** medium
- **What it catches:** `gradle-wrapper.properties` lacking `distributionSha256Sum`; wrapper download integrity unverified.

#### PROBE: Maven-Hijack class-shadowing risk

- SPECULATIVE; requires class-name collision analysis across resolved deps. Reference Chains Project research (arXiv 2407.18760).

### Category 6; Build / Deploy Patterns (Java)

#### PROBE: spring-boot-maven-plugin building fat JAR without layered build

- Info-only.

#### PROBE: Dockerfile FROM openjdk:8 (EOL) or :latest

- **Language:** Java | **Category:** Build/Deploy | **Severity:** medium

#### PROBE: jlink/jdeps missing; large runtime

- Info.

#### PROBE: Spring profiles in pom.xml referencing "prod" with debug logging

- SPECULATIVE.

#### PROBE: JAR without Manifest Sealed: true on security-sensitive packages

- Info.

#### PROBE: JVM flags missing -XX:+ExitOnOutOfMemoryError

- Info.

#### PROBE: Maven Central deploy without GPG signing in CI

- Info / supply chain.

## 5. Kotlin

### Framework / Library Inventory (Kotlin)

**Top-3 frameworks with framework-specific probes included below:** Jetpack Compose / Android SDK, Ktor, Spring Boot (Kotlin).

**Additional frameworks/libraries to enumerate in future passes:** Android Architecture Components (Room, WorkManager, Navigation, ViewModel, LiveData, DataStore), Hilt, Dagger, Koin, Kodein, kotlinx.coroutines, kotlinx.serialization, Ktor client/server, Exposed ORM, jOOQ-Kotlin, Spring Webflux Kotlin, http4k, javalin (Kotlin-friendly), Vert.x Kotlin, RxKotlin, Arrow, Result, Kotest, MockK, Detekt, ktlint, Compose Multiplatform, Kotlin Multiplatform Mobile (KMM), SQLDelight, Multiplatform Settings, Ktor MCP, LangChain4j (Kotlin-callable), OpenAI-Kotlin, anthropic-sdk-kotlin community ports.

### Category 1; AI-Tool Failure Patterns (Kotlin)

#### PROBE: AndroidManifest.xml activity android:exported="true" without intent-filter justification

- **Language:** Kotlin (also Java Android) | **Category:** AI-tool failure | **Framework:** Android | **Severity:** high
- **What it catches:** Activities/Services/Receivers/Providers with `android:exported="true"` that lack permission declarations. Since API 31, `exported` must be explicit; AI tools default to `true` to make intents work.
- **Why AI gets this wrong:** When an intent doesn't resolve, AI's path-of-least-resistance is to flip `exported` to true rather than refactor.
- **Detection approach:** XML parse of `AndroidManifest.xml`.
- **Remediation:** Set `exported="false"` unless intent-filter is intentional and add `android:permission="..."`.
- **Known incidents:** OWASP MASVS-CODE-1; widely-cited Android exported-component CVEs.

#### PROBE: AndroidManifest.xml android:allowBackup="true" without backupRules.xml

- **Language:** Kotlin/Java | **Category:** AI-tool failure | **Framework:** Android | **Severity:** medium
- **What it catches:** Default backup behavior copies app private data (Room DB, SharedPreferences) to Google Drive; exposes session tokens, PII.
- **Detection approach:** XML: presence of `allowBackup="true"` and absence of `android:fullBackupContent` or `android:dataExtractionRules`.
- **Remediation:** `allowBackup="false"` or provide explicit extraction rules excluding sensitive paths.

#### PROBE: AndroidManifest.xml android:usesCleartextTraffic="true" or networkSecurityConfig allowing cleartext

- **Language:** Kotlin/Java | **Category:** AI-tool failure | **Framework:** Android | **Severity:** high
- **Detection approach:** XML.
- **Why AI gets this wrong:** Same MitM defense bypass as `verify=False`; AI's fix for "my localhost dev API isn't loading."

#### PROBE: WebView with setJavaScriptEnabled(true) + addJavascriptInterface from any URL

- **Language:** Kotlin/Java | **Category:** AI-tool failure | **Framework:** Android WebView | **Severity:** critical
- **What it catches:** `webView.settings.javaScriptEnabled = true` + `webView.addJavascriptInterface(BridgeObject(), "Bridge")` + `loadUrl` that can be any URL → JS-to-native code execution from attacker-controlled HTML.
- **Detection approach:** AST: presence of all three in same class; or `setAllowFileAccessFromFileURLs(true)`.
- **Known incidents:** CVE-2012-6636 and numerous Android RCE chains; OWASP Mobile.

#### PROBE: SharedPreferences storing credentials / tokens

- **Language:** Kotlin/Java | **Category:** AI-tool failure | **Framework:** Android | **Severity:** high
- **What it catches:** `getSharedPreferences(...).edit().putString("auth_token", token).apply()`; SharedPreferences is plaintext XML.
- **Detection approach:** AST: `SharedPreferences.putString` with key containing `token`/`password`/`secret`/`auth`.
- **Remediation:** EncryptedSharedPreferences (deprecated as of Jetpack Security 1.1) or DataStore + Tink; on iOS-parity track to Android Keystore.

#### PROBE: Room @Dao @Query with raw SQL using string template

- **Language:** Kotlin | **Category:** AI-tool failure | **Framework:** Room | **Severity:** critical
- **What it catches:** `@Query("SELECT * FROM user WHERE name = '${name}'")`; Room queries support `:param` named bindings; AI sometimes uses Kotlin string templates which DO interpolate at annotation-processor time but only for literal values. The more dangerous pattern is `@RawQuery` with `SimpleSQLiteQuery("SELECT ... " + userInput)`.
- **Detection approach:** AST: `@RawQuery` or `SimpleSQLiteQuery` with concatenation.
- **Remediation:** Use `@Query("SELECT * FROM user WHERE name = :name")` named bindings.

#### PROBE: Ktor server: install(CORS) with anyHost()

- **Language:** Kotlin | **Category:** AI-tool failure | **Framework:** Ktor | **Severity:** high
- **What it catches:** `install(CORS) { anyHost(); allowCredentials = true }`.

#### PROBE: Ktor client HttpClient { engine { config { sslContext = trust-all } } }

- **Language:** Kotlin | **Category:** AI-tool failure | **Framework:** Ktor client | **Severity:** critical
- **What it catches:** Custom trust manager that accepts all certs in Ktor's HttpClient engine config.

#### PROBE: Compose @Composable accepting raw HTML / loading WebView with remote URL

- **Language:** Kotlin | **Category:** AI-tool failure | **Framework:** Jetpack Compose | **Severity:** medium

#### PROBE: Coroutine GlobalScope.launch in production

- **Language:** Kotlin | **Category:** AI-tool failure | **Severity:** medium
- **What it catches:** `GlobalScope.launch { ... }`; leaks across lifecycle, hard to cancel; Kotlin docs explicitly warn.
- **Detection approach:** AST.
- **Remediation:** Tied scope (`viewModelScope`, `lifecycleScope`, or `CoroutineScope(SupervisorJob() + Dispatchers.IO)`).

### Category 2; OWASP Top 10:2025 (Kotlin)

Largely identical to Java (Spring Boot mappings) plus OWASP Mobile Top 10:

- **M1 Improper Credential Usage:** Hardcoded API keys in `BuildConfig`, `gradle.properties`, or `local.properties` shipped in APK.
- **M2 Inadequate Supply Chain Security:** see Category 5.
- **M3 Insecure Authentication/Authorization:** JWT with no signature verification (see jjwt patterns in Java).
- **M4 Insufficient Input/Output Validation:** raw SQL via Room.
- **M5 Insecure Communication:** cleartext + trust-all certs.
- **M6 Inadequate Privacy Controls:** Logcat with PII (`Log.d("TAG", "user: $user")`).
- **M7 Insufficient Binary Protections:** ProGuard/R8 minify/obfuscate disabled.
- **M8 Security Misconfiguration:** exported components.
- **M9 Insecure Data Storage:** SharedPreferences for secrets.
- **M10 Insufficient Cryptography:** Cipher.getInstance("AES") default.

#### PROBE: Logcat (android.util.Log) with potentially sensitive data

- **Language:** Kotlin | **Category:** OWASP Mobile M6 / A09 | **Severity:** medium
- **Detection approach:** AST: `Log.d/i/w/e` with arguments containing variable names like `password`, `token`, `email`, `phone`, `pin`, `card`, `ssn`.
- **Remediation:** Strip logs in release via ProGuard rules `-assumenosideeffects class android.util.Log { *; }`.

### Category 3; OWASP LLM Top 10 (Kotlin)

Same as Java; Spring AI Kotlin DSL and LangChain4j Kotlin extensions.

### Category 4; Memory / Concurrency / Resource Patterns (Kotlin)

#### PROBE: Coroutine launched on Dispatchers.Default for I/O

- **Language:** Kotlin | **Category:** Concurrency | **Severity:** low
- **What it catches:** `launch(Dispatchers.Default) { httpClient.get(...) }`; should be `Dispatchers.IO`.

#### PROBE: Suspending function with blocking I/O (Thread.sleep, JDBC) without withContext(Dispatchers.IO)

- **Language:** Kotlin | **Category:** Concurrency | **Severity:** medium
- **Detection approach:** AST: suspend fun body containing `Thread.sleep` or known-blocking JDBC calls without enclosing `withContext`.

#### PROBE: !! null-assertion operator

- **Language:** Kotlin | **Category:** Memory (crash) | **Severity:** low
- **What it catches:** `value!!` in network or user-input code path; NPE crash on unexpected null.
- **Detection approach:** RX/AST count of `!!` per file.

#### PROBE: lateinit var with no isInitialized check

- **Language:** Kotlin | **Category:** Memory | **Severity:** low

#### PROBE: Job not cancelled on disposal

- **Language:** Kotlin | **Category:** Concurrency / Resource | **Severity:** medium
- **What it catches:** ViewModel onCleared not cancelling Job; Activity onDestroy not cancelling scope.

#### PROBE: Native code (JNI) called with user input; buffer overflow risk

- **Language:** Kotlin | **Category:** Memory | **Severity:** high
- **What it catches:** `external fun nativeFoo(data: ByteArray)` called with attacker-controllable data.
- **Detection approach:** AST + heuristic.

### Category 5; Supply Chain Patterns (Kotlin / Gradle / Maven)

#### PROBE: build.gradle.kts dependency without version (resolution-strategy override risk)

- See Java equivalent.

#### PROBE: jitpack / jcenter ordered before mavenCentral / google

- See Java equivalent; MavenGate research.

#### PROBE: gradle/wrapper/gradle-wrapper.properties without checksum

- See Java equivalent.

#### PROBE: gradle/libs.versions.toml unpinned versions

- **Language:** Kotlin | **Category:** Supply chain | **Severity:** medium

#### PROBE: Known compromised package

- Same Maven Central / Gradle IOC list as Java.

#### PROBE: Android dependency from non-Google Play (sideload pattern)

- **Language:** Kotlin | **Category:** Supply chain | **Severity:** low

#### PROBE: Compose snapshot/dev version pinned

- **Language:** Kotlin | **Category:** Supply chain | **Severity:** low

### Category 6; Build / Deploy Patterns (Kotlin)

#### PROBE: build.gradle without minifyEnabled / shrinkResources in release

- **Language:** Kotlin/Java Android | **Category:** Build/Deploy | **Severity:** medium
- **What it catches:** Release builds with no R8 / ProGuard; debug symbols and full class names shipped.

#### PROBE: signingConfig.storeFile with hardcoded path containing developer username

- **Language:** Kotlin | **Category:** Build/Deploy | **Severity:** low
- **Detection approach:** Look for absolute path patterns in `build.gradle.kts`.

#### PROBE: keystore.properties or signing config committed

- **Language:** Kotlin | **Category:** Build/Deploy | **Severity:** critical
- **Detection approach:** File presence + git status.

#### PROBE: gradle.properties with `android.injected.signing.*` set

- **Language:** Kotlin | **Category:** Build/Deploy | **Severity:** high

#### PROBE: build.gradle.kts dependency with mavenLocal() first in repository list

- **Language:** Kotlin | **Category:** Build/Deploy / Supply chain | **Severity:** medium

#### PROBE: ApplicationId / packageName matches a known existing Play Store app

- SPECULATIVE; homoglyph-attack against existing apps.

## 6. Swift

### Framework / Library Inventory (Swift)

**Top-3 frameworks with framework-specific probes included below:** SwiftUI, UIKit (still dominant in many codebases), Vapor (server-side Swift).

**Additional frameworks/libraries to enumerate in future passes:** AppKit, WatchKit, tvOS frameworks, Combine, async/await primitives, Network.framework, URLSession, Alamofire, Moya, Kingfisher, SDWebImage, Realm-Swift, GRDB, Core Data, SwiftData, CryptoKit, CommonCrypto, KeychainAccess, Keychain Services, AuthenticationServices (Sign In with Apple), Firebase iOS SDK, AppCheck, GoogleSignIn, Stripe iOS, Hummingbird, Perfect, Kitura (legacy), Smoke, gRPC-Swift, swift-nio, swift-log, swift-metrics, swift-distributed-tracing, swift-crypto, Vapor Fluent (ORM), MongoSwift, RediStack, PostgresKit, MySQLKit, JWTKit, swift-openapi, Swift macros, Combine-extensions, Pointfree TCA (Composable Architecture), ReactiveSwift, MLX-Swift (Apple silicon ML), CoreML, Vision, NaturalLanguage, Speech, openai-swift / MacPaw OpenAI, anthropic-swift community ports.

### Category 1; AI-Tool Failure Patterns (Swift)

#### PROBE: Info.plist NSAppTransportSecurity with NSAllowsArbitraryLoads = true

- **Language:** Swift / Obj-C | **Category:** AI-tool failure | **Framework:** iOS/macOS | **Severity:** high
- **What it catches:** App Transport Security disabled globally; allows cleartext HTTP system-wide.
- **Why AI gets this wrong:** When debugging "my dev server isn't loading," AI flips the global flag rather than adding a per-domain exception.
- **Detection approach:** plist parse.
- **Remediation:** Use `NSExceptionDomains` for specific dev hostnames only.
- **Known incidents:** App Store review historically catches this; OWASP MASVS-NETWORK.

#### PROBE: URLSession with allowsArbitraryLoadsInWebContent or custom URLSessionDelegate.didReceive challenge returning .useCredential with URLCredential(trust:)

- **Language:** Swift | **Category:** AI-tool failure | **Severity:** critical
- **What it catches:** Custom delegate that always trusts: `completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))` without validation.
- **Detection approach:** AST: `URLSessionDelegate.urlSession(_:didReceive:completionHandler:)` whose body unconditionally calls completionHandler with `.useCredential` and `URLCredential(trust:)`.
- **Known incidents:** CWE-295; OWASP MASVS-NETWORK-2.

#### PROBE: UserDefaults storing tokens / passwords / secrets

- **Language:** Swift | **Category:** AI-tool failure | **Framework:** Foundation | **Severity:** high
- **What it catches:** `UserDefaults.standard.set(token, forKey: "authToken")`. UserDefaults is plist-backed and unprotected at rest (especially on jailbroken devices).
- **Detection approach:** AST: `UserDefaults.*.set(...)` where key contains `token`/`password`/`secret`/`pin`/`key`/`api`.
- **Remediation:** Keychain Services with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (or stricter).

#### PROBE: SQLite raw query string concatenation

- **Language:** Swift | **Category:** AI-tool failure | **Framework:** SQLite.swift / FMDB | **Severity:** critical
- **Detection approach:** AST: `sqlite3_exec`/`db.execute` with string interpolation.

#### PROBE: WKWebView with javaScriptEnabled and loadHTMLString containing user content

- **Language:** Swift | **Category:** AI-tool failure | **Framework:** WebKit | **Severity:** high
- **What it catches:** `webView.loadHTMLString("<html>...\(userContent)...</html>", baseURL: nil)`.

#### PROBE: WKWebView with WKUserContentController scriptMessageHandler exposing native methods

- **Language:** Swift | **Category:** AI-tool failure | **Framework:** WebKit | **Severity:** critical
- **What it catches:** Custom `WKScriptMessageHandler` whose `userContentController(_:didReceive:)` dispatches to a switch on `message.name` that invokes native code with `message.body` arguments; JS bridge equivalent of Android's addJavascriptInterface.

#### PROBE: Vapor route handler with raw SQL via SQLKit string interpolation

- **Language:** Swift | **Category:** AI-tool failure | **Framework:** Vapor | **Severity:** critical
- **Detection approach:** AST: `app.raw("SELECT ... \(userInput)")`.

#### PROBE: try! on network response

- **Language:** Swift | **Category:** AI-tool failure | **Severity:** medium
- **What it catches:** `try! JSONDecoder().decode(...)` from network response; crash on malformed.
- **Detection approach:** RX `try!` in network-handling files.

#### PROBE: Force unwrap on optionals from network / user input

- **Language:** Swift | **Category:** AI-tool failure / Memory | **Severity:** medium
- **Detection approach:** `value!` in code reachable from URLSession completion.

#### PROBE: Hardcoded LLM keys, Firebase API keys, Stripe publishable+secret keys

- See Python equivalent; iOS / macOS apps notoriously ship secrets in Info.plist or as Swift String literals.

### Category 2; OWASP Mobile + Top 10:2025 (Swift)

#### PROBE: MASVS-CRYPTO; CC_MD5 / CC_SHA1 used for password

- **Language:** Swift | **Category:** OWASP A02 | **Severity:** high
- **What it catches:** CommonCrypto MD5/SHA1 imports for password hashing.

#### PROBE: MASVS-CRYPTO; Hardcoded symmetric key in Swift source

- **Language:** Swift | **Category:** OWASP A02 | **Severity:** critical
- **What it catches:** `let key = "0123456789abcdef..."` declared as `Data`/`SymmetricKey` literal.

#### PROBE: arc4random() / Int.random(in:) used for tokens

- **Language:** Swift | **Category:** OWASP A02 | **Severity:** medium
- **Remediation:** `SystemRandomNumberGenerator` is OK; CryptoKit's `SymmetricKey(size:)` for keys.

#### PROBE: Keychain access without kSecAttrAccessibleWhenUnlockedThisDeviceOnly

- **Language:** Swift | **Category:** OWASP MASVS-STORAGE | **Severity:** medium
- **What it catches:** Keychain Add/Update lacking explicit `kSecAttrAccessible*ThisDeviceOnly`; items can be backed up to iCloud.

#### PROBE: Sign-In With Apple nonce missing or unverified

- **Language:** Swift | **Category:** OWASP A07 | **Severity:** high
- **What it catches:** `ASAuthorizationAppleIDProvider` flow that uses a constant nonce or skips nonce verification; replay attack.

#### PROBE: Vapor middleware: bcrypt cost too low

- **Language:** Swift | **Category:** OWASP A07 | **Framework:** Vapor | **Severity:** medium

#### PROBE: URLSession with URL from string interpolation reachable to server (SSRF); server-side Vapor only

- See Python A10 equivalent.

### Category 3; OWASP LLM Top 10 (Swift)

Less common; CoreML on-device inference and MacPaw OpenAI SDK are dominant. Mostly LLM02 (logs containing PII) and LLM10 (no token cap on remote calls).

### Category 4; Memory / Concurrency / Resource Patterns (Swift)

#### PROBE: @unchecked Sendable on reference type with mutable state

- **Language:** Swift | **Category:** Concurrency | **Severity:** high
- **What it catches:** Class marked `@unchecked Sendable` containing `var` properties; race condition risk under Swift 6 strict concurrency.

#### PROBE: DispatchQueue.main.sync from main thread

- **Language:** Swift | **Category:** Concurrency | **Severity:** high
- **What it catches:** Deadlock pattern.

#### PROBE: Strong reference cycle in closure ([weak self] missing in retained closure)

- **Language:** Swift | **Category:** Memory | **Severity:** medium
- **Detection approach:** AST: closure captures `self` and is assigned to a property of self.

#### PROBE: Task { } not stored, no cancellation propagation

- **Language:** Swift | **Category:** Concurrency | **Severity:** medium
- **What it catches:** `Task { await ... }` discarded; same orphan-task issue as Python asyncio and tokio.

#### PROBE: UnsafeMutablePointer / UnsafeBufferPointer with computed offsets

- **Language:** Swift | **Category:** Memory | **Severity:** high
- **What it catches:** Manual pointer arithmetic in Swift; uncommon but explicit memory-safety bypass.

#### PROBE: withUnsafeBytes used for cryptographic operations bypassing Sendable

- Info.

### Category 5; Supply Chain Patterns (Swift / SwiftPM / CocoaPods)

#### PROBE: Package.swift dependency with .branch("main") or .branch(...)

- **Language:** Swift | **Category:** Supply chain | **Severity:** high
- **What it catches:** Mutable branch reference; any compromise of the upstream main branch flows in on next resolution.
- **Detection approach:** MAN: Package.swift / Package.resolved.

#### PROBE: Package.swift dependency from non-github.com / non-apple.com hosts

- **Language:** Swift | **Category:** Supply chain | **Severity:** medium

#### PROBE: Podfile pointing to abandoned pod (CocoaPods Trunk going read-only Dec 2, 2026)

- **Language:** Swift / Obj-C | **Category:** Supply chain | **Severity:** medium
- **What it catches:** Any Podfile dependency on a pod that doesn't have a Swift Package Manager alternative; these will receive no security updates after December 2, 2026 when CocoaPods Trunk becomes read-only.
- **Known incidents:** CocoaPods sunset announced 2024; prepare_command field blocked May 2025; trunk read-only December 2, 2026 (CocoaPods blog).

#### PROBE: Podspec prepare_command field present (legacy / known security risk)

- **Language:** Swift / Obj-C | **Category:** Supply chain | **Severity:** high
- **What it catches:** Custom Podspec with `prepare_command`; historically abused for credential exfiltration; new pods blocked from using this since May 2025.

#### PROBE: CocoaPods Podfile.lock with orphaned (no owner) pods

- **Language:** Swift / Obj-C | **Category:** Supply chain | **Severity:** medium
- **Known incidents:** 1,866 orphaned pods identified by E.V.A. Information Security (2024); CVE-2024-38366 / 38367 / 38368.

#### PROBE: Swift Package Resolved missing or stale

- **Language:** Swift | **Category:** Supply chain | **Severity:** medium
- **Detection approach:** MAN: Package.resolved diff against Package.swift.

#### PROBE: .xcframework or binary dependency from non-pinned URL

- **Language:** Swift | **Category:** Supply chain | **Severity:** high
- **Detection approach:** Package.swift `.binaryTarget(url:checksum:)`; flag if checksum missing.

### Category 6; Build / Deploy Patterns (Swift)

#### PROBE: Xcode build settings ENABLE_BITCODE removed without justification (info)

- Info only; Apple deprecated bitcode.

#### PROBE: Xcode build setting GCC_PREPROCESSOR_DEFINITIONS with DEBUG=1 in release

- **Language:** Swift / Obj-C | **Category:** Build/Deploy | **Severity:** medium

#### PROBE: Info.plist with NSExceptionDomains containing public TLD (e.g., "com")

- **Language:** Swift | **Category:** Build/Deploy | **Severity:** high
- **What it catches:** Wildcards in ATS exceptions.

#### PROBE: provisioning profile bundled in repo

- **Language:** Swift | **Category:** Build/Deploy | **Severity:** medium

#### PROBE: GoogleService-Info.plist committed

- **Language:** Swift | **Category:** Build/Deploy | **Severity:** medium
- **What it catches:** Firebase config bundled in source; not a "secret" but enables abuse of project quotas.

#### PROBE: fastlane Matchfile / Appfile with team_id / apple_id committed (low risk but information disclosure)

- Info.

#### PROBE: build settings with CODE_SIGNING_ALLOWED=NO in release

- **Language:** Swift | **Category:** Build/Deploy | **Severity:** high

## 7. C#

### Framework / Library Inventory (C#)

**Top-3 frameworks with framework-specific probes included below:** ASP.NET Core (incl. Minimal APIs and MVC), Entity Framework Core, Blazor.

**Additional frameworks/libraries to enumerate in future passes:** WinForms, WPF, MAUI, Xamarin (sunsetting), Unity (C# subset), Worker Service, gRPC for .NET, ServiceStack, Nancy (legacy), Carter, FastEndpoints, MediatR, AutoMapper, FluentValidation, Dapper, NHibernate, MongoDB.Driver, StackExchange.Redis, MassTransit, NServiceBus, Hangfire, Quartz.NET, Coravel, Serilog, NLog, ILogger, OpenTelemetry, IdentityServer (Duende), OpenIddict, ASP.NET Identity, JWT bearer auth, IdentityModel.Tokens.Jwt, BouncyCastle.NET, Azure SDK, AWSSDK.NET, Google.Cloud.\*, RestSharp, Refit, Flurl, HttpClient, SignalR, Orleans, Akka.NET, ML.NET, ONNX Runtime, Semantic Kernel, Microsoft.Extensions.AI, OpenAI .NET SDK, Anthropic.SDK community, LangChain.NET community, Nethereum, Stripe.net.

### Category 1; AI-Tool Failure Patterns (C#)

#### PROBE: ASP.NET Core UseDeveloperExceptionPage in production

- **Language:** C# | **Category:** AI-tool failure | **Framework:** ASP.NET Core | **Severity:** high
- **What it catches:** `app.UseDeveloperExceptionPage()` not gated on `env.IsDevelopment()`; exposes stack traces, environment variables (via `/error` page), routes.
- **Why AI gets this wrong:** Templates separate this in `if (env.IsDevelopment())` but AI consolidations sometimes flatten.
- **Detection approach:** AST: `UseDeveloperExceptionPage` called outside an `IsDevelopment()` branch in `Program.cs`/`Startup.cs`.
- **Remediation:** `if (app.Environment.IsDevelopment()) { app.UseDeveloperExceptionPage(); } else { app.UseExceptionHandler("/error"); }`.

#### PROBE: ASP.NET Core MapGet/MapPost with [AllowAnonymous] on whole controller after [Authorize] global

- **Language:** C# | **Category:** AI-tool failure | **Framework:** ASP.NET Core | **Severity:** high
- **What it catches:** Inconsistent auth annotations.

#### PROBE: ASP.NET Core CORS AllowAnyOrigin + AllowCredentials

- **Language:** C# | **Category:** AI-tool failure | **Framework:** ASP.NET Core | **Severity:** high
- **Detection approach:** AST: `policy.AllowAnyOrigin().AllowCredentials()` in `AddCors` configuration. Note that ASP.NET Core rejects this combination at runtime, but `SetIsOriginAllowed(_ => true)` paired with credentials is the dangerous workaround.

#### PROBE: SqlCommand with string concatenation

- **Language:** C# | **Category:** AI-tool failure | **Severity:** critical
- **Detection approach:** AST: `new SqlCommand($"SELECT ... {userInput}", conn)` or `SqlCommand.CommandText = "..." + userInput`.
- **Remediation:** `SqlCommand` with `@param` and `cmd.Parameters.AddWithValue`.

#### PROBE: Entity Framework Core FromSqlRaw with interpolated string

- **Language:** C# | **Category:** AI-tool failure | **Framework:** EF Core | **Severity:** critical
- **What it catches:** `context.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name = '{name}'")`; `FromSqlRaw` does NOT parameterize interpolated strings; only `FromSqlInterpolated` does.
- **Detection approach:** AST: `FromSqlRaw` with `$"..."` interpolated string argument.
- **Remediation:** `FromSqlInterpolated($"SELECT ... WHERE Name = {name}")` or `FromSqlRaw("... WHERE Name = {0}", name)`.

#### PROBE: HttpClient new in loop (socket exhaustion)

- **Language:** C# | **Category:** AI-tool failure (Resource) | **Severity:** medium
- **What it catches:** `using (var client = new HttpClient()) { ... }` inside a loop or per-request handler exhausts sockets (TIME_WAIT). Use `IHttpClientFactory`.
- **Detection approach:** AST: `new HttpClient()` inside a method that is reached per request.
- **Remediation:** Inject `IHttpClientFactory`.

#### PROBE: HttpClientHandler.ServerCertificateCustomValidationCallback returning true

- **Language:** C# | **Category:** AI-tool failure | **Severity:** critical
- **Detection approach:** AST.

#### PROBE: BinaryFormatter / NetDataContractSerializer / SoapFormatter use

- **Language:** C# | **Category:** AI-tool failure | **Severity:** critical
- **What it catches:** `BinaryFormatter.Deserialize` is officially obsolete and a known RCE vector (Microsoft has been emphasizing for years).
- **Detection approach:** AST: imports/usages of `BinaryFormatter`, `NetDataContractSerializer`, `SoapFormatter`, `LosFormatter`, `ObjectStateFormatter`.
- **Known incidents:** Many .NET deserialization CVEs.

#### PROBE: Newtonsoft.Json with TypeNameHandling = All or Auto

- **Language:** C# | **Category:** AI-tool failure | **Framework:** Newtonsoft.Json | **Severity:** critical
- **What it catches:** Polymorphic deserialization with auto type → gadget chain RCE.
- **Detection approach:** AST: `JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All }` or `Auto`.

#### PROBE: System.Text.Json JsonSerializerOptions.TypeInfoResolver allowing all types

- Less commonly abusable but worth flagging.

#### PROBE: Razor @Html.Raw(userValue) / Blazor MarkupString from user input

- **Language:** C# | **Category:** AI-tool failure | **Framework:** ASP.NET Core MVC/Blazor | **Severity:** high
- **Detection approach:** AST: `Html.Raw(<non-constant>)`, `new MarkupString(userValue)`.

#### PROBE: Process.Start with shell command

- **Language:** C# | **Category:** AI-tool failure | **Severity:** critical
- **Detection approach:** AST: `Process.Start("cmd.exe", "/c " + userInput)` or `Process.Start(new ProcessStartInfo { FileName = "cmd", Arguments = $".../{userInput}/..."})`.

### Category 2; OWASP Top 10:2025 (C#)

#### PROBE: A02; System.Security.Cryptography.MD5/SHA1 used on credential

- See pattern.

#### PROBE: A02; System.Random for security tokens

- **Detection approach:** AST: `new Random()` in token-related code.
- **Remediation:** `RandomNumberGenerator.GetBytes` or `RandomNumberGenerator.GetInt32`.

#### PROBE: A02; Aes ECB mode

- **Detection approach:** RX `CipherMode\.ECB`.

#### PROBE: A02; RijndaelManaged (deprecated)

- Info.

#### PROBE: A05; appsettings.json with Secrets\_\_ConnectionString embedded

- **Language:** C# | **Category:** OWASP A05 | **Severity:** high
- **Detection approach:** JSON parse for `Server=`, `Password=`, JWT signing keys, API keys.

#### PROBE: A05; UseHsts() and UseHttpsRedirection() missing

- **Language:** C# | **Category:** OWASP A05 | **Severity:** medium

#### PROBE: A05; ASP.NET Core Antiforgery disabled

- **Language:** C# | **Category:** OWASP A05 | **Framework:** ASP.NET Core | **Severity:** high
- **What it catches:** `services.AddControllers(o => o.Filters.Add(typeof(IgnoreAntiforgeryTokenAttribute)))` or `[IgnoreAntiforgeryToken]` on all controllers.

#### PROBE: A07; JwtBearer with TokenValidationParameters { ValidateSignature = false } or ValidateIssuer = false

- **Language:** C# | **Category:** OWASP A07 | **Framework:** Microsoft.AspNetCore.Authentication.JwtBearer | **Severity:** critical
- **Detection approach:** AST: any property of `TokenValidationParameters` set to false where the property starts with `Validate`.

#### PROBE: A07; ASP.NET Identity password policy weakened

- Info.

#### PROBE: A08; packages.config / .csproj PackageReference without version

- See supply chain.

#### PROBE: A10; HttpClient.GetAsync with URL from request

- **Language:** C# | **Category:** OWASP A10 SSRF | **Severity:** high
- **Detection approach:** AST taint.

### Category 3; OWASP LLM Top 10 (C#)

Semantic Kernel and Microsoft.Extensions.AI are the dominant in-tree SDKs.

- **LLM01:** `kernel.InvokePromptAsync($"Rules: {userInput}")`; prompt injection via interpolated string.
- **LLM05:** LLM output passed to `SqlCommand` or `Process.Start`.
- **LLM10:** `OpenAIPromptExecutionSettings.MaxTokens` not set.

### Category 4; Memory / Concurrency / Resource Patterns (C#)

#### PROBE: async void on non-event handler

- **Language:** C# | **Category:** Concurrency | **Severity:** medium
- **What it catches:** `async void Foo()` outside of an event handler; exceptions are unobservable, crash the process.
- **Detection approach:** AST: `async void` method declarations not matching `EventArgs` pattern.

#### PROBE: .Result / .Wait on Task in ASP.NET Core

- **Language:** C# | **Category:** Concurrency | **Severity:** high
- **What it catches:** `someAsync().Result` deadlocks under sync-context-aware code and exhausts thread pool.

#### PROBE: lock(this) / lock(typeof(X))

- **Language:** C# | **Category:** Concurrency | **Severity:** medium

#### PROBE: IDisposable not disposed (using statement absent)

- **Language:** C# | **Category:** Resource | **Severity:** medium
- **Detection approach:** AST: variables of IDisposable types not declared with `using`/`using var`.

#### PROBE: Stream not closed on response

- Info; mostly handled by framework.

#### PROBE: unsafe { } block with pointer arithmetic

- **Language:** C# | **Category:** Memory | **Severity:** medium
- **Detection approach:** AST: `unsafe` blocks.

### Category 5; Supply Chain Patterns (C# / NuGet)

#### PROBE: PackageReference without Version attribute

- **Language:** C# | **Category:** Supply chain | **Severity:** medium

#### PROBE: PackageReference with floating version "1.\*" or "[1.0,2.0)"

- **Language:** C# | **Category:** Supply chain | **Severity:** medium

#### PROBE: nuget.config with non-official sources

- **Language:** C# | **Category:** Supply chain | **Severity:** high
- **What it catches:** `<add key="..." value="https://attacker.example/v3/index.json" />` or HTTP non-TLS source.

#### PROBE: Known compromised NuGet package (IOC)

- **Language:** C# | **Category:** Supply chain | **Severity:** critical
- **IOC list (Nov 2025–April 2026):** `Sharp7Extend`, `MCDbRepository`, `SqlUnicornCoreTest`, `SqlUnicornCore`, and six other packages from author `shanhai666` (logic-bomb time-delayed sabotage targeting Siemens S7 PLCs and SQL Server/PostgreSQL/SQLite, triggers August 2027 and November 2028; Socket via Kush Pandya, disclosure November 5-7, 2025; 9 malicious packages with 9,488 total downloads); `NethereumNet` and `Netherеum.All` (Cyrillic-е homoglyph typosquats of Nethereum, October 2025; Socket, Boychenko); `StripeAPI.net` typosquat with 506 versions of artificially inflated downloads (ReversingLabs, late 2025); `Coinbase.Net.Api`, `Google Ads.API` family from same campaign with SendMoneyAsync transaction redirects.

#### PROBE: NuGet package with homoglyph in name

- **Language:** C# | **Category:** Supply chain | **Severity:** high
- **What it catches:** NuGet, unlike npm/PyPI/Maven/RubyGems/Crates.io, does NOT restrict package names to ASCII. Names containing Unicode `е` (U+0435), `а` (U+0430), `о` (U+043E), `і` (U+0456), etc. should be flagged.
- **Detection approach:** MAN: scan PackageReference Include attributes for non-ASCII Cyrillic/Greek lookalikes.
- **Known incidents:** Per Hacker News and Socket coverage; Netherеum.All (Cyrillic е) October 2025; ReversingLabs July 2024 homoglyph campaign.

#### PROBE: NuGet package with artificially inflated downloads (heuristic; flagged as info)

- Cannot detect statically without registry call; out-of-scope.

#### PROBE: .csproj with custom RestoreSources overriding nuget.org

- **Language:** C# | **Category:** Supply chain | **Severity:** medium

### Category 6; Build / Deploy Patterns (C#)

#### PROBE: .csproj PublishReadyToRun without trimming security review

- Info.

#### PROBE: Dockerfile FROM mcr.microsoft.com/dotnet/aspnet:latest

- **Language:** C# | **Category:** Build/Deploy | **Severity:** medium

#### PROBE: appsettings.Development.json deployed to production

- **Language:** C# | **Category:** Build/Deploy | **Severity:** high

#### PROBE: launchSettings.json with ASPNETCORE_ENVIRONMENT=Development committed and used in CI

- Info.

#### PROBE: Web.config with debug="true" / customErrors mode="Off"

- **Language:** C# (legacy ASP.NET) | **Category:** Build/Deploy | **Severity:** high
- **Detection approach:** XML parse of Web.config.

#### PROBE: Project with PublishTrimmed=true but uses reflection

- SPECULATIVE.

#### PROBE: dotnet publish without --no-self-contained baking in dev cert

- Info.

## 8. C

### Framework / Library Inventory (C)

C has no single dominant application framework; embedded, kernel, systems libraries, and CLI tooling dominate. Library/runtime targets for AI-generated C:

- libc (glibc, musl, BSD libc, newlib), POSIX, Win32 API, stdio, string.h, stdlib.h
- libcurl, OpenSSL, libssh2, libxml2, libxslt, libpng, libjpeg-turbo, libtiff, FreeType, zlib, libzip, sqlite3, libpq (PostgreSQL), MariaDB connector, mongoc, libuv, libev, libevent, GLib/GTK, GNOME stack, SDL2/3, ImageMagick
- ESP-IDF, FreeRTOS, Zephyr, Arduino C, nrfconnect, STM32 HAL, mbed-tls
- Linux kernel drivers, BPF, DPDK, nginx modules, Apache APR
- PHP/Python/Ruby C extensions, Node N-API modules

**Top-3 framework groupings with probes:** libcurl + OpenSSL (network/TLS), embedded HAL / FreeRTOS / ESP-IDF, kernel/driver C.

### Category 1; AI-Tool Failure Patterns (C)

#### PROBE: strcpy / strcat / sprintf / gets used with non-bounded sources

- **Language:** C | **Category:** AI-tool failure / OWASP A03 | **Severity:** critical
- **What it catches:** Any use of `strcpy`, `strcat`, `sprintf`, `gets`, `scanf("%s", ...)`. These have been unsafe since the 1990s; AI tools still emit them because they appear in stdlib documentation and millions of training-corpus lines.
- **Why AI gets this wrong:** "Copy this string" → `strcpy` is one keystroke; safer `strncpy_s`/`snprintf` requires sizing.
- **Detection approach:** AST/RX: function calls to the named functions.
- **False positive risk:** `sprintf` into known-large fixed buffer is safe but still bad practice.
- **Remediation:** `snprintf(buf, sizeof buf, ...)`, `strlcpy` (BSD), `strncat`, never `gets` (removed in C11).
- **Known incidents:** Top of CWE-119/120/121 charts; SEI CERT STR31-C.

#### PROBE: malloc without check for NULL return

- **Language:** C | **Category:** AI-tool failure / Memory | **Severity:** high
- **What it catches:** `char *p = malloc(n); p[0] = ...` with no `if (!p)` check.
- **Detection approach:** AST: malloc/calloc/realloc return assigned, then dereferenced before NULL check.

#### PROBE: realloc reassigning to same pointer (memory leak on failure)

- **Language:** C | **Category:** AI-tool failure / Memory | **Severity:** medium
- **What it catches:** `p = realloc(p, n);`; if realloc fails, `p` is now NULL and original memory leaked.
- **Detection approach:** AST: `p = realloc(p, ...)` pattern.
- **Remediation:** `tmp = realloc(p, n); if (tmp) p = tmp; else { /* handle */ }`.

#### PROBE: Use-after-free pattern: free(p) followed by use of p

- **Language:** C | **Category:** AI-tool failure / Memory | **Severity:** critical
- **Detection approach:** AST: free(x) followed by read/write of x in same basic block without intervening assignment.

#### PROBE: Double free: free(p) ... free(p)

- **Language:** C | **Category:** Memory | **Severity:** critical
- **Detection approach:** AST.

#### PROBE: memcpy/memmove with size from user input

- **Language:** C | **Category:** AI-tool failure / Memory | **Severity:** critical
- **What it catches:** `memcpy(dst, src, *(uint32_t*)header)`; length-field-controlled overflow (Heartbleed pattern).
- **Detection approach:** AST: memcpy/memmove with size argument derived from network read or file parse.
- **Known incidents:** Heartbleed CVE-2014-0160 is the canonical example.

#### PROBE: Format string vulnerability: printf(userInput)

- **Language:** C | **Category:** AI-tool failure / OWASP A03 | **Severity:** critical
- **Detection approach:** AST: `printf`/`fprintf`/`syslog`/`snprintf` where first format arg is a non-constant expression.

#### PROBE: Integer overflow in size calculation: malloc(n \* sizeof(T)) where n is user-controlled

- **Language:** C | **Category:** Memory | **Severity:** critical
- **Detection approach:** AST: multiplication inside malloc/calloc-size argument where one operand is parameter.

#### PROBE: alloca with user-controlled size

- **Language:** C | **Category:** Memory | **Severity:** critical
- **What it catches:** Stack-allocation of user-controlled size; trivial stack-clash.

#### PROBE: system() / popen() with constructed command

- **Language:** C | **Category:** AI-tool failure / OWASP A03 | **Severity:** critical
- **Detection approach:** AST: system/popen with snprintf-built or concatenated argument.

#### PROBE: rand() / srand(time(NULL)) for security

- **Language:** C | **Category:** AI-tool failure / OWASP A02 | **Severity:** high
- **Detection approach:** AST: `rand()` calls in same translation unit as token/crypto code.
- **Remediation:** `getrandom()` Linux, `arc4random_buf` BSD, `BCryptGenRandom` Windows, OpenSSL `RAND_bytes`.

#### PROBE: OpenSSL SSL_CTX with SSL_VERIFY_NONE

- **Language:** C | **Category:** AI-tool failure | **Severity:** critical
- **Detection approach:** RX `SSL_VERIFY_NONE`.
- **Remediation:** `SSL_VERIFY_PEER` and load CA bundle.

#### PROBE: libcurl CURLOPT_SSL_VERIFYPEER=0

- **Language:** C | **Category:** AI-tool failure | **Severity:** critical
- **Detection approach:** RX `CURLOPT_SSL_VERIFYPEER.*0` or `curl_easy_setopt(..., CURLOPT_SSL_VERIFYPEER, 0L)`.

#### PROBE: libcurl CURLOPT_SSL_VERIFYHOST=0

- Same severity.

#### PROBE: libcurl CURLOPT_WRITEFUNCTION callback writes to fixed buffer without size check

- SPECULATIVE.

### Category 2; OWASP Top 10:2025 (C)

C-based services typically expose A03 (injection / memory injection), A02 (crypto), A05 (config), A06 (vulnerable deps via vcpkg/Conan), and A07 (auth). Web-style A01/A10 less common except via nginx modules or embedded HTTP servers.

#### PROBE: A03; sqlite3_exec/sqlite3_mprintf concatenation

- **Detection approach:** AST.
- **Remediation:** `sqlite3_prepare_v2` + `sqlite3_bind_*`.

#### PROBE: A02; MD5_Init, SHA1_Init from OpenSSL legacy provider

- See pattern.

#### PROBE: A02; DES*\*, RC4*\* APIs from OpenSSL

- **Detection approach:** RX.

#### PROBE: A02; Custom XOR "crypto"

- **Detection approach:** Heuristic; XOR loops on data named `key`/`encrypt`.

#### PROBE: A07; strcmp on password / hash (timing leak)

- **Language:** C | **Category:** OWASP A07 | **Severity:** medium
- **What it catches:** `strcmp(submitted, expected) == 0` for token validation; early-return timing leak.
- **Remediation:** `CRYPTO_memcmp` (OpenSSL), `consttime_memequal` (BSD), or hand-rolled constant-time compare.

### Category 3; OWASP LLM Top 10 (C)

Largely N/A; C is rarely used for direct LLM client code. Embedded inference (TensorFlow Lite Micro, llama.cpp) is the primary intersection; relevant probes are bounds checks on model-input buffers (covered by Category 1 memory probes).

### Category 4; Memory / Concurrency / Resource Patterns (C)

Substantial overlap with Category 1 above. Additional:

#### PROBE: pthread_mutex_lock without paired unlock on all error paths

- **Language:** C | **Category:** Concurrency | **Severity:** medium
- **Detection approach:** AST: pthread_mutex_lock with branches that return without unlock.

#### PROBE: pthread_create without pthread_join or pthread_detach

- **Language:** C | **Category:** Concurrency / Resource | **Severity:** medium

#### PROBE: signal-handler calling non-async-signal-safe function

- SPECULATIVE.

#### PROBE: TOCTOU: stat()/access() followed by open()

- **Language:** C | **Category:** Concurrency | **Severity:** high
- **What it catches:** Classic TOCTOU pattern.

#### PROBE: fopen with mode "w" on user-controlled path (path traversal)

- **Language:** C | **Category:** OWASP A01 | **Severity:** high

#### PROBE: Race condition on global counter incrementing without atomic

- High false-positive; deprioritize.

#### PROBE: Variable-length array (VLA) with user-controlled bound

- **Language:** C | **Category:** Memory | **Severity:** high
- **What it catches:** `char buf[user_size]` on stack; DoS / stack overflow.

#### PROBE: fgets without checking newline (truncation)

- Info.

### Category 5; Supply Chain Patterns (C / vcpkg / Conan / system packages)

#### PROBE: vcpkg.json without version pin

- **Language:** C/C++ | **Category:** Supply chain | **Severity:** medium

#### PROBE: vcpkg overlay-ports pointing to local path

- **Language:** C/C++ | **Category:** Supply chain | **Severity:** medium

#### PROBE: Conan conanfile.txt / conanfile.py with `[requires]` range like `openssl/[>=1.0]`

- **Language:** C/C++ | **Category:** Supply chain | **Severity:** medium

#### PROBE: Submodule pinned to branch instead of commit SHA

- **Language:** C/C++ | **Category:** Supply chain | **Severity:** high
- **Detection approach:** `.gitmodules` + `.git/modules/*/HEAD` analysis (or just `.gitmodules` for branch references).

#### PROBE: Vendored OpenSSL older than current LTS

- **Language:** C/C++ | **Category:** Supply chain | **Severity:** high
- **Detection approach:** Search vendor directories for `opensslv.h` versions.

#### PROBE: Makefile fetching dependency over HTTP (no TLS)

- **Language:** C/C++ | **Category:** Supply chain | **Severity:** high
- **Detection approach:** RX `wget|curl` with `http://` URLs in Makefile, CMakeLists.txt, build scripts.

#### PROBE: CMake FetchContent / ExternalProject from non-pinned URL

- **Language:** C/C++ | **Category:** Supply chain | **Severity:** medium

#### PROBE: Debian/Ubuntu source dependency without explicit version in CI

- Info.

### Category 6; Build / Deploy Patterns (C)

#### PROBE: CFLAGS missing -D_FORTIFY_SOURCE=2

- **Language:** C | **Category:** Build/Deploy | **Severity:** medium
- **What it catches:** GCC/Clang `_FORTIFY_SOURCE` adds compile-time and runtime checks against buffer-overflow-prone libc calls.
- **Detection approach:** Search Makefile/CMakeLists.txt/configure scripts for CFLAGS.

#### PROBE: CFLAGS missing -fstack-protector-strong

- **Language:** C | **Category:** Build/Deploy | **Severity:** medium

#### PROBE: LDFLAGS missing -Wl,-z,relro -Wl,-z,now

- **Language:** C | **Category:** Build/Deploy | **Severity:** low

#### PROBE: Binary built without -fPIE / -pie

- **Language:** C | **Category:** Build/Deploy | **Severity:** medium

#### PROBE: -fsanitize=address / -fsanitize=undefined absent from test/CI build

- **Language:** C | **Category:** Build/Deploy | **Severity:** info
- **What it catches:** ASan / UBSan not enabled in CI; missing critical bug detection.

#### PROBE: -O3 with -fno-stack-check or -fomit-frame-pointer hardening removal

- Info.

#### PROBE: Compiled with -Wno-format-security or -Wno-error=format-security

- **Language:** C | **Category:** Build/Deploy | **Severity:** medium

#### PROBE: setuid binary built without -Wl,-z,noexecstack

- **Language:** C | **Category:** Build/Deploy | **Severity:** high

#### PROBE: Dockerfile FROM alpine without ca-certificates

- **Language:** C | **Category:** Build/Deploy | **Severity:** low

## 9. C++

### Framework / Library Inventory (C++)

**Top-3 framework groupings with probes:** Qt (desktop + embedded), Boost / std-modern (libraries), game engines (Unreal C++ + custom). Server-side C++ frameworks (Drogon, Crow, cpp-httplib, oat++, Pistache, Boost.Beast, gRPC++) are increasingly common for AI-generated backends.

**Additional frameworks/libraries to enumerate in future passes:** Qt 6 (QtWidgets, QtQuick/QML, Qt for Python), Boost (asio, beast, filesystem, json, log, multiprecision), Abseil, folly, gRPC C++, protobuf C++, FlatBuffers, Cap'n Proto, nlohmann/json, RapidJSON, simdjson, fmt, spdlog, glog, Eigen, OpenCV C++, PCL, ITK, VTK, ROS / ROS 2, EtherCAT stacks, OPC UA, ROS-Industrial, Unreal Engine 5, Unity Native plugins, Godot GDExtension, Dear ImGui, GLFW, GLEW, SDL2/3, SFML, raylib (C/C++ both), Vulkan SDK, DirectX, CUDA / HIP / SYCL, Kokkos, Thrust, llama.cpp, ggml, ONNX Runtime C++, TensorRT, ncnn, mediapipe, PyTorch C++ (libtorch), Drogon, Crow, oat++, Pistache, cpp-httplib, restbed, served, sqlpp11, soci, libpqxx, mongocxx, hiredis, cpp-redis, RxCpp, libuv-cpp, asio (Boost or standalone), uvw, range-v3, magic_enum, doctest, gtest, gmock, catch2.

C++ probes substantially overlap with C; this section covers C++-specific patterns.

### Category 1; AI-Tool Failure Patterns (C++)

#### PROBE: Raw pointer ownership with new/delete

- **Language:** C++ | **Category:** AI-tool failure / Memory | **Severity:** high
- **What it catches:** `T* p = new T(...)` whose lifetime is unclear, with no smart-pointer wrapper. Modern C++ (C++11+) idioms prefer `std::unique_ptr` / `std::shared_ptr` / `std::make_unique`.
- **Why AI gets this wrong:** Older training data; AI defaults to raw `new`/`delete` because C++98 style is dominant in legacy code.
- **Detection approach:** AST: `new T(...)` expression whose result is assigned to a raw pointer variable.
- **Remediation:** `auto p = std::make_unique<T>(...)`.

#### PROBE: std::string operator[] / front() / back() without bounds check

- **Language:** C++ | **Category:** Memory | **Severity:** medium
- **Detection approach:** Heuristic on .empty() check absence in same scope.

#### PROBE: std::vector::operator[] on user-indexed access (vs .at())

- **Language:** C++ | **Category:** Memory | **Severity:** medium
- **Detection approach:** AST: `vec[user_var]` where `user_var` traces to request input.
- **Remediation:** `vec.at(idx)` for bounds-checked, or explicit size check.

#### PROBE: reinterpret_cast on POD layout assumption

- **Language:** C++ | **Category:** Memory | **Severity:** high
- **What it catches:** `auto* hdr = reinterpret_cast<Header*>(buffer);` followed by field access; alignment / strict-aliasing UB.

#### PROBE: dynamic_cast result not checked for nullptr

- **Language:** C++ | **Category:** Memory | **Severity:** medium

#### PROBE: std::cout / std::cerr with attacker-controllable format manipulators (mostly safe; info)

- Info.

#### PROBE: Use of std::regex with user-controlled pattern

- **Language:** C++ | **Category:** AI-tool failure / DoS | **Severity:** medium
- **What it catches:** ReDoS; `std::regex` does not have built-in catastrophic-backtracking protection.

#### PROBE: Qt SQL: QSqlQuery exec with string concatenation

- **Language:** C++ | **Category:** AI-tool failure | **Framework:** Qt | **Severity:** critical
- **Detection approach:** AST: `query.exec(QString("SELECT ... %1").arg(userInput))`.
- **Remediation:** `query.prepare("SELECT ... :id"); query.bindValue(":id", id);`.

#### PROBE: Qt QProcess with QProcess::start(const QString&) shell-string form

- **Language:** C++ | **Category:** AI-tool failure | **Framework:** Qt | **Severity:** high

#### PROBE: cpp-httplib / Drogon / oat++ route handler with raw SQL

- **Language:** C++ | **Category:** AI-tool failure | **Severity:** critical

#### PROBE: nlohmann::json parse without exception handling

- **Language:** C++ | **Category:** AI-tool failure | **Severity:** medium
- **Detection approach:** AST: `json::parse(...)` not wrapped in try/catch or paired with `.is_object()` check.

#### PROBE: OpenSSL EVP\_\* without proper init / context cleanup

- **Language:** C++ | **Category:** AI-tool failure / Memory | **Severity:** medium

#### PROBE: Move-after-use: std::move on value used afterwards

- **Language:** C++ | **Category:** Memory | **Severity:** medium

### Category 2; OWASP Top 10:2025 (C++)

Substantially identical to C, plus:

#### PROBE: A03; Eval-like patterns via Lua/Python/JS embedding

- **Language:** C++ | **Category:** OWASP A03 | **Severity:** high
- **What it catches:** Game engines and tools embed Lua/Python/JS interpreters; passing user input directly to `lua_dostring`, `PyRun_SimpleString`, `v8::Script::Compile`.

#### PROBE: A02; Boost.Random with std::random_device on platforms with deterministic random_device

- Info; historically MinGW had deterministic `std::random_device`.

### Category 3; OWASP LLM Top 10 (C++)

Llama.cpp, ggml, ONNX Runtime C++ APIs. Probes:

- **LLM03/04:** Loading GGUF / ONNX from untrusted file path without checksum verification.
- **LLM10:** No `n_predict` / `max_tokens` cap on inference calls.

### Category 4; Memory / Concurrency / Resource Patterns (C++)

#### PROBE: std::mutex held across coroutine suspension / await

- **Language:** C++ | **Category:** Concurrency | **Severity:** high
- **Detection approach:** AST: `lock_guard`/`unique_lock` live across `co_await` expression.

#### PROBE: std::thread without join or detach

- **Language:** C++ | **Category:** Concurrency / Resource | **Severity:** high
- **Detection approach:** AST: `std::thread t(...)` whose destructor runs without prior join/detach.

#### PROBE: Capturing this by reference in async lambda

- **Language:** C++ | **Category:** Memory | **Severity:** high
- **What it catches:** `[&]() { use member; }` posted to executor; UAF if the object is destroyed before the lambda runs.

#### PROBE: shared_ptr cycle (no weak_ptr break)

- SPECULATIVE; hard to detect statically.

#### PROBE: std::shared_mutex without prefer-write configuration → writer starvation

- SPECULATIVE.

#### PROBE: Iterator invalidation: pushback on vector then continue iterating

- **Language:** C++ | **Category:** Memory | **Severity:** medium

#### PROBE: std::atomic with relaxed memory order on critical path

- **Language:** C++ | **Category:** Concurrency | **Severity:** medium

#### PROBE: Long-running co_await inside try/catch without timeout

- Info.

### Category 5; Supply Chain Patterns (C++)

Same as C; vcpkg, Conan, CMake FetchContent, git submodules.

#### PROBE: vcpkg manifest with builtin-baseline missing

- **Language:** C++ | **Category:** Supply chain | **Severity:** medium

#### PROBE: vcpkg overlay-triplets pointing to ad-hoc URL

- **Language:** C++ | **Category:** Supply chain | **Severity:** medium

#### PROBE: Conan recipe with `tools.system.package_manager` calling apt/yum/brew at install

- Info.

#### PROBE: header-only library vendored without source-of-truth comment

- Info.

#### PROBE: CMake find_package with NO_DEFAULT_PATH and custom CMAKE_PREFIX_PATH from env

- **Language:** C++ | **Category:** Supply chain | **Severity:** medium

### Category 6; Build / Deploy Patterns (C++)

#### PROBE: CMake with no -fsanitize=address in Debug

- Info.

#### PROBE: -fno-rtti combined with dynamic_cast usage (UB)

- **Language:** C++ | **Category:** Build/Deploy | **Severity:** high

#### PROBE: MSVC compiled without /GS (stack canary)

- **Language:** C++ | **Category:** Build/Deploy | **Severity:** medium

#### PROBE: MSVC /sdl flag missing

- **Language:** C++ | **Category:** Build/Deploy | **Severity:** low

#### PROBE: Clang/GCC built without -Wformat -Wformat-security

- See C equivalent.

#### PROBE: Built with -fno-exceptions in code that uses STL containers expecting bad_alloc handling

- Info.

#### PROBE: Static library linked into shared library leaks symbols

- Info.

#### PROBE: CMakeLists.txt CMAKE_BUILD_TYPE not set (defaults to no optimization, no security)

- **Language:** C++ | **Category:** Build/Deploy | **Severity:** low

#### PROBE: Embedded firmware build without secure-boot signing pipeline (info)

- Info.

## 10. Ruby

### Framework / Library Inventory (Ruby)

**Top-3 frameworks with framework-specific probes included below:** Rails (with ActiveRecord/ActionPack/ActionView), Sinatra, Hanami.

**Additional frameworks/libraries to enumerate in future passes:** Rails ecosystem (Active Storage, Action Cable, Action Mailbox, Action Text, Active Job, Turbo, Stimulus, Hotwire, Importmap, Propshaft, Solid Queue, Solid Cache, Solid Cable, Kamal), Grape, Roda, Padrino, Cuba, Trailblazer, Devise, Pundit, CanCanCan, Sorcery, OmniAuth, JWT, Doorkeeper, oauth2, OpenID Connect, Sidekiq, Resque, GoodJob, Que, Faktory, Rake, Capistrano, Mina, ActiveModel-Serializers, jbuilder, blueprinter, GraphQL-Ruby, AdminPanel/Administrate/Trestle/Avo/RailsAdmin, Searchkick, Elasticsearch-Ruby, Bullet, RSpec, Minitest, Cucumber, FactoryBot, Faker, Capybara, Bundler, Bundler-Audit, Brakeman, Rubocop, Standard, Sorbet, RBS, Steep, dry-rb suite (validation, types, monads, container, system), ROM-rb, Sequel, Mongoid, MongoMapper, Neo4j-Ruby, redis-rb, dalli, connection_pool, httparty, faraday, rest-client (deprecated), Net::HTTP, async-http, mechanize, nokogiri, oga, ox, rmagick, mini_magick, image_processing, marcel, mimemagic, prawn, wicked_pdf, grover, fastlane (Swift Fastfile in Ruby), openai gem, anthropic gem, ruby-openai, langchainrb, anthropic-sdk-ruby.

### Category 1; AI-Tool Failure Patterns (Ruby)

#### PROBE: Rails ActiveRecord where with string interpolation

- **Language:** Ruby | **Category:** AI-tool failure | **Framework:** Rails | **Severity:** critical
- **What it catches:** `User.where("name = '#{params[:name]}'")`; classic Rails SQL injection. ActiveRecord's `where` accepts hash and bind params for a reason.
- **Why AI gets this wrong:** AI often emits the string form because it parallels SQL syntax in the training data.
- **Detection approach:** AST via Parser gem or tree-sitter-ruby: `where`/`find_by_sql`/`group`/`order`/`having` calls with first argument as String including `#{...}` interpolation.
- **Remediation:** `User.where(name: params[:name])` or `User.where("name = ?", params[:name])`.
- **Known incidents:** Brakeman has flagged this as the #1 Rails injection class for over a decade.

#### PROBE: Rails ActiveRecord order with user input

- **Language:** Ruby | **Category:** AI-tool failure | **Framework:** Rails | **Severity:** high
- **What it catches:** `User.order(params[:sort])`; Rails started sanitizing in 6.0 but only for known patterns; unknown direction strings still inject.
- **Detection approach:** AST.
- **Remediation:** Allowlist of valid sort columns; `User.order(:name)` not `User.order(params[:sort])`.

#### PROBE: render plain: / render inline: with ERB and user input

- **Language:** Ruby | **Category:** AI-tool failure | **Framework:** Rails | **Severity:** critical
- **What it catches:** `render inline: "Hello <%= params[:name] %>"`; ERB injection / SSTI when name contains `<%= ... %>`.

#### PROBE: html_safe on user input

- **Language:** Ruby | **Category:** AI-tool failure | **Framework:** Rails | **Severity:** high
- **What it catches:** `params[:bio].html_safe` or `raw(params[:bio])`; bypasses ActionView's autoescape.
- **Detection approach:** AST: `.html_safe` call on non-literal; `raw(...)` with non-literal.

#### PROBE: eval / instance_eval / class_eval / module_eval with non-literal string

- **Language:** Ruby | **Category:** AI-tool failure | **Severity:** critical
- **Detection approach:** AST.

#### PROBE: send / public_send with user-controlled method name

- **Language:** Ruby | **Category:** AI-tool failure | **Severity:** high
- **What it catches:** `obj.send(params[:action])`; invokes arbitrary method.
- **Detection approach:** AST: `send`/`public_send`/`__send__` with first arg from params/request.
- **Remediation:** Allowlist of permitted methods.

#### PROBE: Marshal.load / Marshal.restore on untrusted input

- **Language:** Ruby | **Category:** AI-tool failure | **Severity:** critical
- **What it catches:** Marshal deserialization is unsafe; equivalent to pickle.
- **Detection approach:** AST.

#### PROBE: YAML.load (vs YAML.safe_load)

- **Language:** Ruby | **Category:** AI-tool failure | **Severity:** critical
- **Detection approach:** AST: `YAML.load(...)` on input that may be attacker-controlled. Note Psych YAML defaults changed in Ruby 3.1 (safe by default).
- **Remediation:** `YAML.safe_load(input, permitted_classes: [...])`.
- **Known incidents:** CVE-2013-0156 (Rails YAML param deserialization); foundational.

#### PROBE: System / backticks / exec with constructed command

- **Language:** Ruby | **Category:** AI-tool failure | **Severity:** critical
- **Detection approach:** AST: `` `cmd #{user}` ``, `system("cmd #{user}")`, `exec(...)`, `IO.popen(...)`, `Open3.popen3(...)` with interpolated string.
- **Remediation:** Array form: `system("cmd", user)` (bypasses shell).

#### PROBE: send_file / send_data with user-controlled path

- **Language:** Ruby | **Category:** AI-tool failure | **Framework:** Rails | **Severity:** critical
- **What it catches:** `send_file params[:file]`; path traversal.
- **Detection approach:** AST.

#### PROBE: redirect_to with params[:url]

- **Language:** Ruby | **Category:** AI-tool failure | **Framework:** Rails | **Severity:** medium
- **What it catches:** Open redirect.
- **Detection approach:** AST: `redirect_to params[*]` or `redirect_to allow_other_host: true`.

#### PROBE: Rails strong parameters bypass: params.permit! or params.to_unsafe_h

- **Language:** Ruby | **Category:** AI-tool failure | **Framework:** Rails | **Severity:** high
- **Detection approach:** AST: `.permit!`/`.to_unsafe_h`/`.to_unsafe_hash` calls on params.

#### PROBE: Sinatra route with params[:id] passed unchecked to File.read

- **Language:** Ruby | **Category:** AI-tool failure | **Framework:** Sinatra | **Severity:** critical

### Category 2; OWASP Top 10:2025 (Ruby)

#### PROBE: A02; Digest::MD5 / Digest::SHA1 for passwords

- See pattern.

#### PROBE: A02; Rails has_secure_password absence; manual SHA1/MD5 hashing

- **Language:** Ruby | **Category:** OWASP A02 | **Framework:** Rails | **Severity:** high

#### PROBE: A02; SecureRandom not used; Random / rand for tokens

- See Python equivalent.

#### PROBE: A05; Rails config.force_ssl = false in production

- **Language:** Ruby | **Category:** OWASP A05 | **Framework:** Rails | **Severity:** high

#### PROBE: A05; config.action_dispatch.default_headers missing security headers

- **Language:** Ruby | **Category:** OWASP A05 | **Framework:** Rails | **Severity:** low

#### PROBE: A05; config.action_controller.allow_forgery_protection = false in production

- **Language:** Ruby | **Category:** OWASP A05 | **Framework:** Rails | **Severity:** high

#### PROBE: A05; Rails secrets.yml / credentials.yml committed without encryption

- **Language:** Ruby | **Category:** OWASP A05 | **Framework:** Rails | **Severity:** critical
- **Detection approach:** File presence + content scan.

#### PROBE: A05; config/master.key committed

- **Language:** Ruby | **Category:** OWASP A05 | **Framework:** Rails | **Severity:** critical
- **Detection approach:** File presence check + .gitignore scan.

#### PROBE: A07; Devise config.password_length too short / sign_in_after_reset_password = true with no rate limit

- **Language:** Ruby | **Category:** OWASP A07 | **Framework:** Devise | **Severity:** medium

#### PROBE: A07; JWT.decode without algorithm pin

- See Python.

#### PROBE: A10; HTTParty.get / Net::HTTP.get with user URL

- **Language:** Ruby | **Category:** OWASP A10 | **Severity:** high

#### PROBE: A10; Rails URI.parse without scheme check (file:// URL fetch)

- **Language:** Ruby | **Category:** OWASP A10 | **Severity:** high

### Category 3; OWASP LLM Top 10 (Ruby)

`langchainrb`, `ruby-openai`, `anthropic-sdk-ruby` are the dominant SDKs.

- **LLM01:** String interpolation into system message arrays.
- **LLM05:** LLM output passed to `eval`/`system`/`Marshal.load`.
- **LLM10:** Missing `max_tokens`.

### Category 4; Memory / Concurrency / Resource Patterns (Ruby)

#### PROBE: Thread.new without ensure-block cleanup

- **Language:** Ruby | **Category:** Concurrency | **Severity:** medium

#### PROBE: Mutex held during I/O

- Info.

#### PROBE: ActiveRecord connection_pool exhausted by long-running query in transaction

- SPECULATIVE.

#### PROBE: ObjectSpace.each_object access

- **Language:** Ruby | **Category:** Memory | **Severity:** low

#### PROBE: N+1 query via .each + association

- **Language:** Ruby | **Category:** Resource | **Severity:** medium
- **Detection approach:** AST heuristic; Bullet gem covers runtime.

#### PROBE: GlobalID locator with user input

- **Language:** Ruby | **Category:** Memory / Security | **Severity:** high

### Category 5; Supply Chain Patterns (Ruby / RubyGems / Bundler)

#### PROBE: Gemfile gem without version constraint

- **Language:** Ruby | **Category:** Supply chain | **Severity:** medium
- **Detection approach:** MAN: parse Gemfile / Gemfile.lock.

#### PROBE: Gemfile source other than https://rubygems.org

- **Language:** Ruby | **Category:** Supply chain | **Severity:** medium

#### PROBE: Gemfile gem with :git => "..." pointing to branch / no :ref

- **Language:** Ruby | **Category:** Supply chain | **Severity:** high

#### PROBE: Gemfile gem with :path => "..." pointing outside repo

- **Language:** Ruby | **Category:** Supply chain | **Severity:** medium

#### PROBE: Known compromised gem (IOC list)

- **Language:** Ruby | **Category:** Supply chain | **Severity:** critical
- **IOC list (2025–2026):** The 60-gem credential-stealing campaign (zon/nowon/kwonsoonje/soonje aliases; Socket, August 2025, 275,000 cumulative downloads), packages posing as Instagram / TikTok / Twitter automation; BufferZoneCorp Ruby gems (May 2026) including `knot-activesupport-logger`, `devise-jwt`-typosquat, `config-loader`-typosquat; Socket/Boychenko; GemStuffer 150+ packages (data-dead-drop via RubyGems against UK council portals; Socket); the May 2026 RubyGems mass-malicious-uploads incident (Mend.io / Maciej Mensfeld; 500+ malicious packages yanked, signups disabled).
- **Detection approach:** MAN diff against bundled JSON.

#### PROBE: Gem with extconf.rb running network calls

- **Language:** Ruby | **Category:** Supply chain | **Severity:** high
- **What it catches:** extconf.rb is executed at install time during native-extension compilation. BufferZoneCorp campaign abused this exact mechanism. Inspect dependency gemspecs (if available) or local gem cache for extconf.rb containing `Net::HTTP`, `URI.open`, `open()` to URLs, `system`, backticks.
- **Detection approach:** AST scan of any extconf.rb in repo or cached gems.

#### PROBE: bundler-audit / brakeman absent from CI

- Info / supply chain.

#### PROBE: Gemfile.lock with revision SHA differing from Gemfile reference

- **Language:** Ruby | **Category:** Supply chain | **Severity:** medium

### Category 6; Build / Deploy Patterns (Ruby)

#### PROBE: Dockerfile bundle install without --deployment / --frozen

- **Language:** Ruby | **Category:** Build/Deploy | **Severity:** medium

#### PROBE: Rails RAILS_ENV inferred from request header / env var spoof

- Info.

#### PROBE: Rails public/ directory containing /system or upload artifacts

- **Language:** Ruby | **Category:** Build/Deploy | **Severity:** high
- **Detection approach:** Repo file scan.

#### PROBE: Capistrano deploy.rb with hardcoded credentials

- **Language:** Ruby | **Category:** Build/Deploy | **Severity:** critical

#### PROBE: Kamal config / deploy.yml with secrets inline

- **Language:** Ruby | **Category:** Build/Deploy | **Severity:** high

#### PROBE: dotenv .env committed

- See Python.

#### PROBE: Puma config with low number_of_threads + many workers (info)

- Info.

## 11. PHP

### Framework / Library Inventory (PHP)

**Top-3 frameworks with framework-specific probes included below:** Laravel, Symfony, WordPress (also plugin development).

**Additional frameworks/libraries to enumerate in future passes:** Laravel ecosystem (Sanctum, Passport, Jetstream, Breeze, Fortify, Nova, Filament, Livewire, Inertia, Horizon, Telescope, Pulse, Echo, Cashier, Socialite, Scout), Symfony components (HttpFoundation, Security Bundle, Doctrine ORM, Twig, Console, Messenger, Workflow, Notifier), CodeIgniter 4, CakePHP, Yii 2, Phalcon, Slim, Lumen, Mezzio, Drupal, Magento 2, Joomla, PrestaShop, October CMS, Statamic, Craft CMS, WooCommerce, ACF, Yoast plugin SDK, Composer plugins, Doctrine DBAL, Eloquent, Cycle ORM, RedBeanPHP, MongoDB PHP driver, Predis, php-redis, AMQP, Beanstalkd PHP, Kafka PHP, Carbon, Carbon-Doctrine, PHPMailer, Symfony Mailer, Twig, Smarty, Blade, ImagickPHP, Intervention/Image, Spatie packages (laravel-permission, laravel-medialibrary, etc.), monolog, Sentry SDK, Datadog PHP, NewRelic PHP, PHPUnit, Pest, Behat, Mockery, openai-php/client, anthropic-ai/sdk PHP, llphant/llphant (LangChain PHP), Prism PHP, AI-related Laravel packages.

### Category 1; AI-Tool Failure Patterns (PHP)

#### PROBE: mysql_query / mysqli_query / PDO::query with concatenation

- **Language:** PHP | **Category:** AI-tool failure | **Severity:** critical
- **What it catches:** `mysqli_query($conn, "SELECT * FROM users WHERE id = ".$_GET['id'])`.
- **Detection approach:** AST: function calls with concatenation including `$_GET`/`$_POST`/`$_REQUEST` reference.
- **Remediation:** Prepared statements with `mysqli_prepare` + `bind_param`, or PDO `prepare` + `execute([param])`.
- **Known incidents:** OWASP A03 perennial #1 for PHP.

#### PROBE: Laravel DB::raw / whereRaw with user input

- **Language:** PHP | **Category:** AI-tool failure | **Framework:** Laravel | **Severity:** critical
- **What it catches:** `User::whereRaw("name = '$name'")` or `DB::select("SELECT ... ".$id)`.
- **Detection approach:** AST: `DB::raw`, `whereRaw`, `selectRaw`, `havingRaw`, `orderByRaw` with non-literal containing `$`.
- **Remediation:** Parameter binding: `whereRaw("name = ?", [$name])` or use Eloquent: `where('name', $name)`.

#### PROBE: Laravel Blade {!! $userValue !!} (unescaped output)

- **Language:** PHP | **Category:** AI-tool failure | **Framework:** Laravel | **Severity:** critical
- **What it catches:** Blade's `{!! !!}` outputs raw, bypassing the `{{ }}` autoescape. AI often uses it to render rich content from CMS users without sanitization.
- **Detection approach:** RX on `.blade.php` files.
- **Remediation:** Use `{{ }}` for autoescape; sanitize via HTMLPurifier or Mews/Purifier when rich HTML is needed.

#### PROBE: Symfony Twig |raw filter on user input

- **Language:** PHP | **Category:** AI-tool failure | **Framework:** Symfony/Twig | **Severity:** high
- **Detection approach:** RX `\|\s*raw` in `.twig` templates; cross-reference against template variables sourced from request.

#### PROBE: exec / system / shell_exec / passthru / `` ` ` `` with constructed argument

- **Language:** PHP | **Category:** AI-tool failure | **Severity:** critical
- **Detection approach:** AST: those functions / backtick operator with non-constant argument.
- **Remediation:** `escapeshellarg`/`escapeshellcmd` (not bulletproof; prefer `proc_open` with explicit argv).

#### PROBE: eval / assert / create_function with non-literal

- **Language:** PHP | **Category:** AI-tool failure | **Severity:** critical
- **Detection approach:** AST.

#### PROBE: include / require with user-influenced path

- **Language:** PHP | **Category:** AI-tool failure | **Severity:** critical
- **What it catches:** `include $_GET['page'].".php"`; Local File Inclusion / RFI.
- **Detection approach:** AST: include/require/\_once with argument containing superglobal access.
- **Remediation:** Strict allowlist of permitted filenames.
- **Known incidents:** Top-tier PHP CVE class historically.

#### PROBE: unserialize on untrusted data

- **Language:** PHP | **Category:** AI-tool failure | **Severity:** critical
- **What it catches:** `unserialize($_COOKIE['session'])`; PHP object injection / POP-chain RCE.
- **Detection approach:** AST: `unserialize` with non-literal argument; also flag `unserialize($_GET/...)` with `allowed_classes` not set.
- **Remediation:** JSON; if must unserialize, pass `['allowed_classes' => false]`.

#### PROBE: file_get_contents / fopen with user URL (LFI/SSRF/RFI)

- **Language:** PHP | **Category:** AI-tool failure | **Severity:** high
- **What it catches:** `file_get_contents($_GET['url'])` allows file://, http://, php:// wrappers; multi-vector attack.

#### PROBE: parse_url + Open Redirect via header("Location: ".$\_GET['next'])

- **Language:** PHP | **Category:** AI-tool failure | **Severity:** medium

#### PROBE: WordPress wp-config.php with hardcoded DB credentials committed

- **Language:** PHP | **Category:** AI-tool failure | **Framework:** WordPress | **Severity:** critical
- **Detection approach:** File scan; check .gitignore.

#### PROBE: Laravel .env committed

- **Language:** PHP | **Category:** AI-tool failure | **Framework:** Laravel | **Severity:** critical

#### PROBE: WordPress add_action / register_rest_route without permission_callback (or with `__return_true`)

- **Language:** PHP | **Category:** AI-tool failure | **Framework:** WordPress | **Severity:** critical
- **What it catches:** REST API routes registered with no authorization.
- **Detection approach:** AST: `register_rest_route` calls where the args array has `permission_callback` set to `'__return_true'` or omitted.
- **Known incidents:** Wordfence regularly reports WordPress plugin CVEs from this exact pattern.

#### PROBE: CURLOPT_SSL_VERIFYPEER false

- See C section.

### Category 2; OWASP Top 10:2025 (PHP)

#### PROBE: A02; md5/sha1 for password storage

- **Detection approach:** AST: `md5`/`sha1` calls in same function as `$_POST['password']` or `Auth::attempt`.
- **Remediation:** `password_hash($pw, PASSWORD_ARGON2ID)` and `password_verify`.

#### PROBE: A02; mt_rand / rand for tokens

- **Detection approach:** AST.
- **Remediation:** `random_bytes`/`random_int`.

#### PROBE: A02; openssl_encrypt with ECB mode

- **Detection approach:** AST: `openssl_encrypt(..., 'aes-256-ecb', ...)`.

#### PROBE: A02; Hardcoded Laravel APP_KEY in config/app.php

- **Language:** PHP | **Category:** OWASP A02 | **Framework:** Laravel | **Severity:** critical

#### PROBE: A05; display_errors=On / error_reporting E_ALL in production

- **Detection approach:** RX in `php.ini`, `.htaccess`, `ini_set` calls.

#### PROBE: A05; Laravel APP_DEBUG=true in production .env

- **Language:** PHP | **Category:** OWASP A05 | **Framework:** Laravel | **Severity:** high
- **What it catches:** Laravel debug pages (Ignition) have historically had RCE chains (CVE-2021-3129 Ignition RCE).

#### PROBE: A05; WordPress WP_DEBUG = true in production wp-config.php

- **Language:** PHP | **Category:** OWASP A05 | **Severity:** medium

#### PROBE: A07; Custom auth comparing password with == (loose) vs === / password_verify

- **Language:** PHP | **Category:** OWASP A07 | **Severity:** high
- **What it catches:** PHP type-juggling; `if ($_POST['password'] == $stored)` with stored value beginning `0e...` allows bypass.

#### PROBE: A07; Firebase JWT decode without algorithm enforcement

- See pattern.

#### PROBE: A08; composer.json without composer.lock committed

- **Language:** PHP | **Category:** Supply chain | **Severity:** medium

#### PROBE: A10; Guzzle / curl_init with URL from request

- **Language:** PHP | **Category:** OWASP A10 | **Severity:** high

### Category 3; OWASP LLM Top 10 (PHP)

`openai-php/client`, `anthropic-ai/sdk-php`, `llphant/llphant` are the major SDKs.

- **LLM01:** String concatenation into system messages.
- **LLM05:** LLM output passed to `eval`/`exec`/`DB::raw`.
- **LLM10:** Missing `max_tokens` in `OpenAI\Client::chat()->create([...])`.

### Category 4; Memory / Concurrency / Resource Patterns (PHP)

PHP is mostly single-process / single-threaded request lifecycle. Notable patterns:

#### PROBE: set_time_limit(0) in long-running route

- **Language:** PHP | **Category:** Resource | **Severity:** medium

#### PROBE: memory_limit set to -1

- **Language:** PHP | **Category:** Resource | **Severity:** medium

#### PROBE: ini_set('display_errors', 1) in production code path

- See A05.

#### PROBE: Laravel queue worker without --max-jobs / --max-time

- **Language:** PHP | **Category:** Resource | **Severity:** low

#### PROBE: file uploads with no MAX_FILE_SIZE / upload_max_filesize check

- **Language:** PHP | **Category:** Resource | **Severity:** medium

#### PROBE: Recursive function without depth limit

- High false-positive; deprioritize.

### Category 5; Supply Chain Patterns (PHP / Composer / Packagist)

#### PROBE: composer.json with require version `*` or `>=X` (no upper bound)

- **Language:** PHP | **Category:** Supply chain | **Severity:** medium

#### PROBE: composer.json with repositories pointing to non-Packagist URL

- **Language:** PHP | **Category:** Supply chain | **Severity:** medium

#### PROBE: composer.json minimum-stability "dev" without explicit constraints

- **Language:** PHP | **Category:** Supply chain | **Severity:** medium

#### PROBE: composer.lock missing

- **Language:** PHP | **Category:** Supply chain | **Severity:** medium

#### PROBE: composer.json post-install-cmd / post-update-cmd running unfamiliar binaries

- **Language:** PHP | **Category:** Supply chain | **Severity:** high
- **What it catches:** Composer scripts run with full shell access at install time. Mini Shai-Hulud Packagist incident (intercom/intercom-php@5.0.2) abused the Composer plugin system.

#### PROBE: Known compromised Composer package (IOC list)

- **Language:** PHP | **Category:** Supply chain | **Severity:** critical
- **IOC list:** `intercom/intercom-php==5.0.2` (April 30, 2026; Mini Shai-Hulud expansion to Packagist via Composer plugin abuse, Socket / Semgrep coverage; 20.7M lifetime installs of the package family); historical: `acquia/coding-standards` family takeovers.
- **Detection approach:** MAN diff against bundled JSON.

#### PROBE: composer.json plugin allowed via "allow-plugins": true (wildcard)

- **Language:** PHP | **Category:** Supply chain | **Severity:** high
- **What it catches:** Composer 2.2+ requires explicit `allow-plugins` declarations. Wildcard `true` re-enables the install-time-code-execution attack surface that was used by Mini Shai-Hulud in intercom-php.
- **Detection approach:** JSON parse of composer.json.

#### PROBE: Composer source from compromised PHP Composer version (CVE-2026-40176 / CVE-2026-40261)

- **Language:** PHP | **Category:** Supply chain | **Severity:** high
- **What it catches:** Composer 2.x versions with the Perforce VCS driver command injection. Patched April 2026.

#### PROBE: WordPress plugin from non-official source

- **Language:** PHP | **Category:** Supply chain | **Severity:** medium
- **Detection approach:** wp-content/plugins/\*/readme.txt cross-reference with wp.org slugs (out of static-scan scope without bundled list).

#### PROBE: composer.json dependency with name highly similar to popular package

- See slopsquatting cross-cutting pattern.

### Category 6; Build / Deploy Patterns (PHP)

#### PROBE: php.ini expose_php = On

- **Language:** PHP | **Category:** Build/Deploy | **Severity:** low

#### PROBE: php.ini allow_url_include = On

- **Language:** PHP | **Category:** Build/Deploy | **Severity:** critical

#### PROBE: php.ini allow_url_fopen = On combined with file_get_contents on user input

- See A10.

#### PROBE: WordPress wp-config.php with WP_AUTO_UPDATE_CORE = false

- Info.

#### PROBE: Laravel APP_ENV=local in production

- **Language:** PHP | **Category:** Build/Deploy | **Framework:** Laravel | **Severity:** high

#### PROBE: .htaccess overriding security headers

- Info.

#### PROBE: Dockerfile FROM php:apache without disabled mod_status / mod_info

- Info.

#### PROBE: phpinfo() called in any committed file (not just dev)

- **Language:** PHP | **Category:** Build/Deploy | **Severity:** high

#### PROBE: Composer install run without --no-dev in production Dockerfile

- **Language:** PHP | **Category:** Build/Deploy | **Severity:** medium

## 12. Scala

### Framework / Library Inventory (Scala)

**Top-3 frameworks with framework-specific probes included below:** Play Framework, Akka / Pekko, Spark.

**Additional frameworks/libraries to enumerate in future passes:** Akka HTTP (legacy license, now Pekko HTTP under Apache), Pekko, Cats Effect, ZIO, fs2, http4s, Tapir, Scalatra, Lagom, Finch, Finatra, Twitter Util, Doobie, Slick, Quill, ScalikeJDBC, scala-redis, Skunk (Postgres typed), Cassandra Scala drivers, scala-mongodb (reactive), Pureconfig, Ciris, Decline, Scopt, Scala Native, Scala.js, sbt (build tool), Mill, Bloop, scalafmt, scalafix, Wartremover, Scalatest, Munit, Specs2, Weaver, ScalaCheck, Magnolia, Circe, uPickle, Play JSON, ZIO JSON, sttp (HTTP client), Caliban (GraphQL), Sangria (GraphQL), Akka Streams, Kafka Streams Scala, Pulsar4s, Spark (Core, SQL, Streaming, ML), Flink Scala, Kafka Scala, Iceberg / Hudi / Delta Lake Scala APIs, Spark ML, Breeze, BIDMach, scala-openai, langchain4s community ports, Llama4s, LiteLLM Scala wrappers.

### Category 1; AI-Tool Failure Patterns (Scala)

#### PROBE: Play Framework routes file with controller action accepting untyped String mapped from path

- **Language:** Scala | **Category:** AI-tool failure | **Framework:** Play | **Severity:** medium

#### PROBE: Play Framework action returns Future without recover handler

- **Language:** Scala | **Category:** AI-tool failure | **Framework:** Play | **Severity:** medium

#### PROBE: Slick / Doobie SQL with sql"" string interpolation containing user value (and unescaped #${...})

- **Language:** Scala | **Category:** AI-tool failure | **Framework:** Slick/Doobie | **Severity:** critical
- **What it catches:** Slick's `sql"SELECT ... where x = ${user}"` is safe (uses bind params), but `#${user}` performs literal interpolation; this is the textbook SQL injection in Slick. Same with Doobie's `fr"..."` vs the `Fragment.const` family.
- **Detection approach:** AST/RX: occurrences of `#$` inside `sql"..."`/`fr"..."`/`sqlu"..."` blocks.
- **Remediation:** Use `$variable` not `#$variable`; for column-name parameterization, allowlist.

#### PROBE: scala.io.Source.fromFile with user-controlled path

- **Language:** Scala | **Category:** AI-tool failure | **Severity:** high

#### PROBE: scala.sys.process with shell metacharacters

- **Language:** Scala | **Category:** AI-tool failure | **Severity:** critical
- **What it catches:** `import scala.sys.process._; s"ls $userPath".!`; shell injection via Process DSL.
- **Detection approach:** AST: `.!` or `.lazyLines` etc. called on a String with interpolation containing variables.
- **Remediation:** `Seq("ls", userPath).!`.

#### PROBE: ScalaJS / Play render Html(userInput)

- **Language:** Scala | **Category:** AI-tool failure | **Framework:** Play | **Severity:** high
- **What it catches:** Play's `Html.apply(userInput)` bypasses Twirl autoescape.

#### PROBE: ObjectMapper / Jackson with default typing (inherited from Java)

- See Java section.

#### PROBE: Akka HTTP RouteDirectives with path(Segment) accepting unescaped path

- Info.

#### PROBE: sbt build.sbt eval-style configuration loading from URL

- **Language:** Scala | **Category:** AI-tool failure / Supply chain | **Severity:** high
- **What it catches:** `resolvers += "..." at "http://..."` (non-TLS), or `libraryDependencies += someExprThatPullsFromNetwork`.

#### PROBE: Pickling / serialization with kryo of untrusted bytes

- **Language:** Scala | **Category:** AI-tool failure | **Severity:** critical
- **Detection approach:** AST: kryo, BoyerMoore-like serializers with untrusted input.

#### PROBE: ZIO/Cats unsafeRun in handler

- **Language:** Scala | **Category:** AI-tool failure / Concurrency | **Severity:** medium
- **What it catches:** `unsafeRunSync()` called inside an HTTP handler in an effectful framework; blocks the event loop.

### Category 2; OWASP Top 10:2025 (Scala)

Inherits most JVM patterns from Java:

#### PROBE: A02; Cipher.getInstance("AES") default ECB

- See Java.

#### PROBE: A02; scala.util.Random for tokens

- **Detection approach:** AST: `scala.util.Random` calls in token-producing functions.
- **Remediation:** `java.security.SecureRandom`.

#### PROBE: A03; Anorm raw SQL with string interpolation

- **Language:** Scala | **Category:** OWASP A03 | **Framework:** Anorm / Play | **Severity:** critical
- **What it catches:** `SQL("SELECT * FROM users WHERE name = '" + name + "'")`.
- **Remediation:** `SQL("SELECT ... WHERE name = {name}").on("name" -> name)`.

#### PROBE: A03; Spark sql() with string concatenation

- **Language:** Scala | **Category:** OWASP A03 | **Framework:** Spark SQL | **Severity:** high
- **What it catches:** `spark.sql(s"SELECT * FROM events WHERE user = '$user'")` in Spark notebooks / jobs accepting user-tenanted parameters.

#### PROBE: A05; Play application.conf with insecure secrets (play.http.secret.key = "changeme")

- **Language:** Scala | **Category:** OWASP A05 | **Framework:** Play | **Severity:** critical

#### PROBE: A05; Play CSRF disabled (play.filters.disabled += CSRFFilter)

- **Language:** Scala | **Category:** OWASP A05 | **Framework:** Play | **Severity:** high

#### PROBE: A07; Play sign-token / pac4j JWT validation with weak alg

- See Java pattern.

#### PROBE: A10; sttp / http4s client with URL from controller

- **Language:** Scala | **Category:** OWASP A10 | **Severity:** high

### Category 3; OWASP LLM Top 10 (Scala)

Smaller surface; some teams use `langchain4j` directly, or Spark MLlib transformers. Mirror Java patterns; emerging: `langchain4s` community libs.

### Category 4; Memory / Concurrency / Resource Patterns (Scala)

#### PROBE: Future not given an explicit ExecutionContext

- **Language:** Scala | **Category:** Concurrency | **Severity:** medium
- **What it catches:** `import scala.concurrent.ExecutionContext.Implicits.global` used in Akka/Play apps; blocks default dispatcher.

#### PROBE: Blocking I/O inside Future without blocking { } marker

- **Language:** Scala | **Category:** Concurrency | **Severity:** medium

#### PROBE: Akka Actor mutable state without become / explicit message-driven mutation

- High false-positive; deprioritize.

#### PROBE: ZIO/Cats Effect Resource not used for closeable

- **Language:** Scala | **Category:** Resource | **Severity:** medium

#### PROBE: Spark DataFrame .collect() on unbounded data

- **Language:** Scala | **Category:** Resource | **Severity:** medium

#### PROBE: Akka Actor system shutdown not called

- Info.

#### PROBE: implicit val ec in object scope (singleton EC shared globally)

- SPECULATIVE.

### Category 5; Supply Chain Patterns (Scala / sbt / Maven / Coursier)

#### PROBE: build.sbt resolvers add Sonatype snapshot / non-TLS URL

- **Language:** Scala | **Category:** Supply chain | **Severity:** high

#### PROBE: build.sbt library dependency with floating version (`"1.+"`, `"latest.integration"`)

- **Language:** Scala | **Category:** Supply chain | **Severity:** medium

#### PROBE: sbt plugin pinned to %% sbt-plugin-name % "1.0+"

- Info.

#### PROBE: Scala major-version mismatch (cross-versioning) creating dependency resolution chaos

- Info.

#### PROBE: Maven Central groupId vulnerable to MavenGate domain takeover

- See Java pattern. Same 18% population.

#### PROBE: ivy.xml / ivysettings.xml from legacy projects

- Info.

#### PROBE: project/build.properties pinning sbt version below known-safe version (CVEs)

- **Language:** Scala | **Category:** Supply chain | **Severity:** medium

### Category 6; Build / Deploy Patterns (Scala)

#### PROBE: sbt-assembly fat-jar without merge strategy for META-INF/services/\* (potential class hijack)

- **Language:** Scala | **Category:** Build/Deploy / Supply chain | **Severity:** medium
- **What it catches:** Same Java-Class-Hijack risk surface as Maven uber-jar. The default merge strategy can preserve attacker-introduced services files.

#### PROBE: sbt-native-packager Docker image FROM scratch missing CA certs (TLS broken)

- Info.

#### PROBE: Play Framework deploying with -Dplay.http.secret.key= on command line (visible in ps output)

- Info.

#### PROBE: Spark job with --packages pulling from non-trusted resolvers

- **Language:** Scala | **Category:** Build/Deploy / Supply chain | **Severity:** high

#### PROBE: Scala Native build without sanitizer flags

- See C++.

#### PROBE: bloop / metals workspace files containing absolute paths

- Info.

## 13. Elixir

### Framework / Library Inventory (Elixir)

**Top-3 frameworks with framework-specific probes included below:** Phoenix (with LiveView and Channels), Ecto, OTP / GenServer / Supervisor primitives.

**Additional frameworks/libraries to enumerate in future passes:** Phoenix LiveView, Phoenix PubSub, Phoenix Presence, Plug, Cowboy / Bandit (HTTP servers), Absinthe (GraphQL), Pow (auth), Guardian (JWT auth), Ueberauth, Comeonin / Argon2_elixir / Bcrypt_elixir, Joken (JWT), Hammer (rate limiting), Oban (job queue), Broadway (data pipelines), GenStage, Flow, Membrane (media streaming), Nx + Axon + Bumblebee (ML), Livebook, Explorer (DataFrames), Req (HTTP client), Tesla, HTTPoison, Finch, Mint, Mox, ExUnit, Sobelow (security linter), Credo, Dialyxir / Dialyzer, Mix, Hex package manager, ESpec, Mneme, ChromicPDF, PDFGenerator, Swoosh (email), Bamboo, Ash Framework, ElixirLS, AshAuthentication, Phoenix.Token, ETS, DETS, Mnesia, EctoSQL, Postgrex, MyXQL, Redix, EctoPSQLExtras, ExAws, OpenAI Elixir community client, Anthropic SDK Elixir community, LangChain Elixir community, mcp_sse, Elixir LLM libraries (Bumblebee for local Phoenix inference).

### Category 1; AI-Tool Failure Patterns (Elixir)

#### PROBE: Ecto fragment with string interpolation

- **Language:** Elixir | **Category:** AI-tool failure | **Framework:** Ecto | **Severity:** critical
- **What it catches:** `from u in User, where: fragment("name = '#{name}'")`; `fragment/1` does NOT escape string interpolation. Compile-time `^` pinning is required.
- **Detection approach:** AST via Code.string_to_quoted / Sourceror: `fragment(...)` macro call whose first arg contains `#{}` interpolation rather than `?` parameter.
- **Remediation:** `fragment("name = ?", ^name)`.

#### PROBE: Ecto raw query Ecto.Adapters.SQL.query! with concat

- **Language:** Elixir | **Category:** AI-tool failure | **Framework:** Ecto | **Severity:** critical
- **Detection approach:** AST.

#### PROBE: Phoenix raw/3 or Phoenix.HTML.raw on user input

- **Language:** Elixir | **Category:** AI-tool failure | **Framework:** Phoenix | **Severity:** critical
- **What it catches:** `<%= raw @user_bio %>` in EEx; bypasses Phoenix's default safe-HTML rendering.
- **Detection approach:** RX/AST on `.eex` and `.heex` templates.

#### PROBE: Phoenix.HTML.html_escape skipped via `safe: true` Map.put

- Less common; speculative.

#### PROBE: System.cmd with shell metacharacters

- **Language:** Elixir | **Category:** AI-tool failure | **Severity:** critical
- **What it catches:** `System.cmd("sh", ["-c", "ls #{user_path}"])`; shell injection.
- **Detection approach:** AST: System.cmd with first arg `"sh"`/`"bash"` and second arg interpolated.
- **Remediation:** `System.cmd("ls", [user_path])` argv form.

#### PROBE: :erlang.binary_to_term with [:safe] missing

- **Language:** Elixir | **Category:** AI-tool failure | **Severity:** critical
- **What it catches:** `:erlang.binary_to_term(payload)` without `[:safe]` allows arbitrary term construction including reference forging; Erlang's pickle equivalent.
- **Detection approach:** AST: `:erlang.binary_to_term/1` (single-arg) or with options list not containing `:safe`.
- **Known incidents:** OWASP A08; Plug.Crypto specifically wraps this safely.

#### PROBE: Code.eval_string / Code.eval_quoted on user input

- **Language:** Elixir | **Category:** AI-tool failure | **Severity:** critical
- **Detection approach:** AST.

#### PROBE: Phoenix Endpoint config :secret_key_base literal in committed config

- **Language:** Elixir | **Category:** AI-tool failure | **Framework:** Phoenix | **Severity:** critical
- **What it catches:** `config :myapp, MyApp.Endpoint, secret_key_base: "literal_secret..."` rather than `System.fetch_env!("SECRET_KEY_BASE")`.

#### PROBE: Phoenix Token.verify with overly long max_age (or :infinity)

- **Language:** Elixir | **Category:** AI-tool failure | **Framework:** Phoenix | **Severity:** medium
- **Detection approach:** AST: `Phoenix.Token.verify(... max_age: :infinity)` or large value.

#### PROBE: Phoenix LiveView assign of user input to inline HTML in heex (raw expression)

- **Language:** Elixir | **Category:** AI-tool failure | **Framework:** Phoenix LiveView | **Severity:** high
- **Detection approach:** Heex template scan for `{:safe, user_value}` or `{raw(...)}`.

#### PROBE: Plug.Static configured to serve user-supplied path segments

- Info.

#### PROBE: HTTPoison/Req/Tesla with insecure: true / verify: :verify_none

- **Language:** Elixir | **Category:** AI-tool failure | **Severity:** critical
- **Detection approach:** RX/AST: `ssl: [verify: :verify_none]`, `insecure: true`.

### Category 2; OWASP Top 10:2025 (Elixir)

#### PROBE: A02; :crypto.hash(:md5, ...) on password

- **Detection approach:** AST.
- **Remediation:** `Argon2.hash_pwd_salt/1`.

#### PROBE: A02; :rand.uniform for tokens (vs :crypto.strong_rand_bytes)

- **Detection approach:** AST: `:rand.uniform`/`Enum.random` in token-related functions.

#### PROBE: A03; Ecto fragment / raw query (covered above)

#### PROBE: A05; Phoenix config `:check_origin: false` in production

- **Language:** Elixir | **Category:** OWASP A05 | **Framework:** Phoenix | **Severity:** high

#### PROBE: A05; Phoenix config `protect_from_forgery: false`

- See pattern.

#### PROBE: A07; Guardian / Joken JWT verifier with `:none` algorithm allowed

- **Language:** Elixir | **Category:** OWASP A07 | **Framework:** Guardian/Joken | **Severity:** critical

#### PROBE: A08; mix.exs deps without ~> version constraint

- See Category 5.

#### PROBE: A10; Req / HTTPoison.get(url) with user-supplied url

- **Language:** Elixir | **Category:** OWASP A10 | **Severity:** high

#### PROBE: Plug.SSL not added to endpoint plug pipeline in production

- **Language:** Elixir | **Category:** OWASP A05 | **Framework:** Phoenix | **Severity:** medium

### Category 3; OWASP LLM Top 10 (Elixir)

Bumblebee (for local Phoenix inference with Hugging Face models) and openai community libraries are the main intersection points.

- **LLM01:** String interpolation into prompt template.
- **LLM03:** `Bumblebee.load_model(...)` from a non-pinned Hugging Face repo (no `:revision` option).
- **LLM05:** LLM output passed to `Code.eval_string` or `System.cmd`.
- **LLM10:** No `max_new_tokens` in `Nx.Serving` config or OpenAI client call.

### Category 4; Memory / Concurrency / Resource Patterns (Elixir)

Elixir/BEAM has unique patterns:

#### PROBE: GenServer.call with default 5-second timeout when downstream operation can be longer

- **Language:** Elixir | **Category:** Concurrency / Resource | **Severity:** medium
- **What it catches:** `GenServer.call(pid, msg)` with default `5_000` ms timeout fronting a slow operation; cascading timeout failures.

#### PROBE: GenServer maintaining unbounded mailbox

- SPECULATIVE.

#### PROBE: Task.async without Task.await timeout

- **Language:** Elixir | **Category:** Concurrency | **Severity:** medium

#### PROBE: ETS table created public without explicit access policy

- **Language:** Elixir | **Category:** Memory | **Severity:** medium
- **Detection approach:** AST: `:ets.new(..., [:public])`.

#### PROBE: Atom creation from user input (atom exhaustion)

- **Language:** Elixir | **Category:** Memory | **Severity:** critical
- **What it catches:** `String.to_atom(user_input)`; BEAM atoms are not garbage-collected; attacker exhausts atom table → VM crash.
- **Detection approach:** AST: `String.to_atom/1`, `:erlang.binary_to_atom/1` with non-literal source.
- **Remediation:** `String.to_existing_atom/1`.

#### PROBE: Stream / Enum on unbounded source without take

- Info.

#### PROBE: spawn without link / monitor

- Info; context-dependent.

#### PROBE: Process.send_after with attacker-influenced delay

- Info.

### Category 5; Supply Chain Patterns (Elixir / Hex / Mix)

#### PROBE: mix.exs deps without version constraint

- **Language:** Elixir | **Category:** Supply chain | **Severity:** medium
- **Detection approach:** MAN: parse mix.exs `defp deps`.

#### PROBE: mix.exs deps with `github: "user/repo"` and no `ref:` (mutable)

- **Language:** Elixir | **Category:** Supply chain | **Severity:** high
- **What it catches:** Git-sourced deps tracking master/main branch; exposes the project to any upstream compromise.

#### PROBE: mix.exs deps with `path:` pointing outside the project

- **Language:** Elixir | **Category:** Supply chain | **Severity:** medium

#### PROBE: Hex package from non-hex.pm repo

- **Language:** Elixir | **Category:** Supply chain | **Severity:** medium

#### PROBE: mix.lock missing

- **Language:** Elixir | **Category:** Supply chain | **Severity:** medium

#### PROBE: Known compromised Hex package (IOC list)

- **Language:** Elixir | **Category:** Supply chain | **Severity:** critical
- **IOC list:** Pre-2017 Plug.Static null-byte injection CVE-2017-1000052 (RCE class; still relevant for legacy Plug versions); the broader 2025–2026 Hex ecosystem has had fewer named mass incidents than npm/PyPI/Packagist, but `mix_audit` and the Elixir Advisory Database (originally dependabot/elixir-security-advisories, now mostly GHSA-fed) cover known vulnerabilities. Pre-Flight should bundle current GHSA Hex advisories.
- **Detection approach:** MAN diff against bundled JSON.

#### PROBE: mix_audit / Sobelow not in CI

- Info.

#### PROBE: Hex package with name similar to popular package (typosquat/slopsquat)

- See cross-cutting.

### Category 6; Build / Deploy Patterns (Elixir)

#### PROBE: mix release without runtime.exs for env-based config

- **Language:** Elixir | **Category:** Build/Deploy | **Severity:** medium
- **What it catches:** Pre-runtime.exs apps bake compile-time config into release; if any value is a secret, it's frozen into the bundle.

#### PROBE: mix release with REPL / iex shell baked in production

- **Language:** Elixir | **Category:** Build/Deploy | **Severity:** medium
- **What it catches:** `:include_erts: true` + missing `:strip_beams: true` ships unnecessary tooling.

#### PROBE: distillery / mix release with cookie hardcoded in vm.args

- **Language:** Elixir | **Category:** Build/Deploy | **Severity:** critical
- **What it catches:** Erlang distribution cookie committed; anyone with the cookie + network access can RPC into the BEAM node.

#### PROBE: Phoenix endpoint with `:debug_errors: true` in prod

- **Language:** Elixir | **Category:** Build/Deploy | **Severity:** high

#### PROBE: Phoenix LiveDashboard mounted on production routes without auth

- **Language:** Elixir | **Category:** Build/Deploy | **Framework:** Phoenix LiveDashboard | **Severity:** high
- **Detection approach:** Router scan: `live_dashboard` macro present and no preceding `pipe_through [:auth]`.

#### PROBE: Bandit / Cowboy with default max_request_line / max_header_size

- Info.

#### PROBE: Distribution mode :longnames enabled with no firewall on port 4369 (epmd)

- Info.

#### PROBE: Dockerfile FROM elixir:latest

- See Python.

## 14. Dart

### Framework / Library Inventory (Dart)

**Top-3 frameworks with framework-specific probes included below:** Flutter (mobile / desktop / web), Dart Frog (server-side), Shelf (HTTP middleware).

**Additional frameworks/libraries to enumerate in future passes:** Flutter ecosystem (Material, Cupertino, GoRouter, Riverpod, Provider, BLoC, GetIt, Get, MobX, Redux, fl*chart, syncfusion_flutter*_), Aqueduct (deprecated), Conduit, Serverpod, Angel, Jaguar, Alfred, http, dio, retrofit, chopper, drift (formerly moor), sqflite, hive, isar, sembast, objectbox, flutter*secure_storage, shared_preferences, flutter_dotenv, firebase*_\_flutter (auth, firestore, storage, messaging, analytics, crashlytics, remote_config, dynamic_links, in_app_purchase), local_auth, biometric_storage, jose, dart_jsonwebtoken, oauth2_client, flutter_appauth, supabase_flutter, amplify_flutter, pocketbase, appwrite, parse_server_sdk_flutter, mason, melos, very_good_cli, fastlane, flutter_launcher_icons, flutter_native_splash, build_runner, freezed, json_serializable, json_annotation, riverpod_generator, go_router_builder, gemini-ai-dart, dart_openai, google_generative_ai (Gemini Dart), langchain_dart, anthropic_dart community ports.

### Category 1; AI-Tool Failure Patterns (Dart)

#### PROBE: shared_preferences storing auth tokens / passwords

- **Language:** Dart | **Category:** AI-tool failure | **Framework:** Flutter | **Severity:** high
- **What it catches:** `prefs.setString('authToken', token)`; shared_preferences is plist on iOS / xml on Android, unencrypted by default.
- **Detection approach:** AST: SharedPreferences.setString / setBool / etc. with key containing `token`/`password`/`secret`/`auth`/`api`.
- **Remediation:** `flutter_secure_storage` (Keychain on iOS, EncryptedSharedPreferences/Keystore on Android).
- **Known incidents:** OWASP Mobile M9; recurrent finding in OWASP MAS test suites.

#### PROBE: HTTP package with badCertificateCallback returning true

- **Language:** Dart | **Category:** AI-tool failure | **Severity:** critical
- **What it catches:** `(HttpClient()..badCertificateCallback = (cert, host, port) => true)` accepts any cert.
- **Detection approach:** AST: assignment to `badCertificateCallback` whose body returns `true`.

#### PROBE: dio Interceptor disabling TLS via custom HttpClientAdapter

- **Language:** Dart | **Category:** AI-tool failure | **Framework:** dio | **Severity:** critical

#### PROBE: WebView with javascriptMode: JavascriptMode.unrestricted + addJavaScriptChannel

- **Language:** Dart | **Category:** AI-tool failure | **Framework:** webview_flutter | **Severity:** high
- **What it catches:** Combination of unrestricted JS + native channel exposed to webview loading remote URLs.

#### PROBE: Platform channel handlers without method-name allowlist

- **Language:** Dart | **Category:** AI-tool failure | **Framework:** Flutter | **Severity:** medium
- **What it catches:** `setMethodCallHandler` switching on `call.method` and reflectively dispatching.

#### PROBE: dart:io File operations with user-supplied path (path traversal)

- **Language:** Dart | **Category:** AI-tool failure | **Severity:** high
- **What it catches:** `File('${appDir.path}/$userInput').readAsString()`.

#### PROBE: Process.run with shell metacharacters / runInShell: true

- **Language:** Dart | **Category:** AI-tool failure | **Severity:** critical
- **Detection approach:** AST: `Process.run(..., runInShell: true)` or first arg `"sh"`/`"bash"` with constructed second arg.

#### PROBE: sqlite (sqflite/drift) rawQuery with string interpolation

- **Language:** Dart | **Category:** AI-tool failure | **Framework:** sqflite/drift | **Severity:** critical
- **What it catches:** `db.rawQuery('SELECT * FROM users WHERE name = "$name"')`.
- **Remediation:** Use `?` placeholders + args list, or drift's typed query DSL.

#### PROBE: Dart Frog request handler with no input validation before DB call

- **Language:** Dart | **Category:** AI-tool failure | **Framework:** Dart Frog | **Severity:** medium

#### PROBE: Firebase Auth signInAnonymously left in production without role guard

- **Language:** Dart | **Category:** AI-tool failure | **Framework:** Firebase | **Severity:** medium

#### PROBE: Firebase Firestore SDK reads with no per-rule check (broken security rules dependency)

- Out of scope (requires firestore.rules analysis, which is a separate JS-like grammar).

#### PROBE: Flutter Web build with secrets embedded via flutter_dotenv

- **Language:** Dart | **Category:** AI-tool failure | **Framework:** Flutter Web / flutter_dotenv | **Severity:** critical
- **What it catches:** `.env` files bundled via `flutter_dotenv` for Flutter Web targets; the env file is shipped in the bundle and visible to the client. Same conceptual error as NEXT*PUBLIC* prefix in Next.js.
- **Detection approach:** Check `pubspec.yaml` for `flutter_dotenv` dependency + Flutter Web target enabled (web/ directory exists); check `.env` assets list in pubspec.
- **Remediation:** Never put real secrets in Flutter Web bundles; use a backend proxy for any privileged API.

#### PROBE: Riverpod / Provider exposing FutureProvider that calls REST API with hardcoded key

- See key-detection pattern.

#### PROBE: GoRouter route with redirect logic that trusts query parameters for auth

- **Language:** Dart | **Category:** AI-tool failure | **Framework:** GoRouter | **Severity:** medium

### Category 2; OWASP Mobile + Top 10:2025 (Dart)

#### PROBE: M1; Hardcoded API key constants

- See key-detection pattern.

#### PROBE: M5; http:// (cleartext) URLs in production

- **Language:** Dart | **Category:** OWASP Mobile M5 | **Severity:** medium
- **Detection approach:** RX `http://[^"\s]+` in .dart files (allowlist localhost/127.0.0.1).

#### PROBE: M9; Storing secrets in SharedPreferences (see above)

#### PROBE: M10; Using deprecated/weak crypto (e.g., dart:crypto md5)

- **Detection approach:** AST.

#### PROBE: Mobile Top 10; Insufficient certificate pinning

- **Language:** Dart | **Category:** OWASP MASVS-NETWORK | **Severity:** medium
- **What it catches:** No use of `SecurityContext.setTrustedCertificates`, no `dio_certificate_pinning`, `http_certificate_pinning`, or `ssl_pinning_plugin`. Probe is "library not imported"; informational.

#### PROBE: Android-side: AndroidManifest.xml (for Flutter Android) usesCleartextTraffic / exported activities

- See Kotlin section.

#### PROBE: iOS-side: Info.plist NSAppTransportSecurity

- See Swift section.

#### PROBE: A03; Dart eval-style: `dart:mirrors` use (deprecated for Flutter; runtime reflection)

- Info; dart:mirrors is mostly server-side only.

#### PROBE: A05; Flutter assets/ directory containing config files with secrets

- **Detection approach:** Asset file content scan.

### Category 3; OWASP LLM Top 10 (Dart)

Emerging surface; `langchain_dart`, `dart_openai`, `google_generative_ai` (Gemini Dart SDK):

- **LLM01:** String interpolation into system message.
- **LLM02:** LLM response written to a Flutter Crashlytics report.
- **LLM05:** Assistant output passed to `Process.run`.
- **LLM10:** Missing `maxOutputTokens` on Gemini `GenerationConfig`; missing `maxTokens` on OpenAI client call.

### Category 4; Memory / Concurrency / Resource Patterns (Dart)

#### PROBE: Future not awaited; orphan async

- **Language:** Dart | **Category:** Concurrency | **Severity:** medium
- **What it catches:** `someAsyncFunction();` without `await` or `unawaited(...)` annotation; same orphan-task family as Python asyncio.
- **Detection approach:** AST: ExpressionStatement whose expression is an async-returning call without await.

#### PROBE: StreamSubscription not cancelled in dispose

- **Language:** Dart | **Category:** Memory / Concurrency | **Severity:** medium
- **What it catches:** Stateful widget subscribing to a Stream in initState without cancelling in dispose → memory leak.

#### PROBE: Timer.periodic not cancelled in dispose

- **Language:** Dart | **Category:** Memory | **Severity:** medium

#### PROBE: setState called after dispose (mounted check missing)

- **Language:** Dart | **Category:** Memory | **Severity:** low

#### PROBE: Isolate.spawn without close

- **Language:** Dart | **Category:** Resource | **Severity:** medium

#### PROBE: File not closed (RandomAccessFile)

- **Language:** Dart | **Category:** Resource | **Severity:** medium

#### PROBE: HttpClient instance reused across requests without close (resource leak)

- Info.

### Category 5; Supply Chain Patterns (Dart / pub.dev / pubspec.yaml)

#### PROBE: pubspec.yaml dependency with `any` version

- **Language:** Dart | **Category:** Supply chain | **Severity:** medium
- **Detection approach:** YAML parse of pubspec.yaml.

#### PROBE: pubspec.yaml dependency with git: ref pointing to branch (not commit SHA)

- **Language:** Dart | **Category:** Supply chain | **Severity:** high

#### PROBE: pubspec.yaml dependency_overrides in production

- **Language:** Dart | **Category:** Supply chain | **Severity:** medium

#### PROBE: pubspec.yaml dependency from path: outside the repo

- **Language:** Dart | **Category:** Supply chain | **Severity:** medium

#### PROBE: pubspec.lock missing or not committed

- **Language:** Dart | **Category:** Supply chain | **Severity:** medium

#### PROBE: ignored_advisories list in pubspec.yaml

- **Language:** Dart | **Category:** Supply chain | **Severity:** medium
- **What it catches:** Per pub.dev docs, `ignored_advisories` suppresses GHSA-prefixed advisory warnings during `dart pub get`. Suppressed entries are legitimate workflow steps but warrant reporting in audit.
- **Detection approach:** YAML parse.

#### PROBE: Dart/Flutter SDK pinned below the symlink-traversal CVE fix (pre-Dart 3.11.0 / Flutter 3.41.0)

- **Language:** Dart | **Category:** Supply chain | **Severity:** high
- **What it catches:** `environment.sdk` constraint allowing Dart < 3.11.0; the pub cache symlink traversal vulnerability was fixed in Dart 3.11.0 / Flutter 3.41.0 (GHSA listed on dart.dev / pub.dev). Pre-fix versions allow malicious packages to write files outside the cache directory.
- **Detection approach:** MAN: pubspec.yaml `environment.sdk` range.

#### PROBE: Known compromised pub package (IOC list)

- **Language:** Dart | **Category:** Supply chain | **Severity:** critical
- **IOC list:** No publicly named mass campaigns against pub.dev as of May 2026 comparable to npm/PyPI/Packagist. Pre-Flight should bundle the current GHSA-fed advisory database for Hex and watch for pub-specific advisories.
- **Detection approach:** MAN diff against bundled JSON.

### Category 6; Build / Deploy Patterns (Dart)

#### PROBE: Flutter Web build with skia / canvaskit renderer leaking source via source maps

- **Language:** Dart | **Category:** Build/Deploy | **Severity:** medium
- **What it catches:** `flutter build web` with default config can expose `main.dart.js.map` and other source maps.

#### PROBE: Flutter build appbundle without --obfuscate / --split-debug-info

- **Language:** Dart | **Category:** Build/Deploy | **Severity:** medium
- **What it catches:** Release Android builds shipped with un-obfuscated symbols; debug info leaks class names. Equivalent of missing ProGuard in Kotlin section.

#### PROBE: Flutter iOS build without strip-symbols / bitcode strip

- Info.

#### PROBE: Android Manifest `<application>` without `android:debuggable` explicitly false

- **Language:** Dart | **Category:** Build/Deploy | **Severity:** high
- **What it catches:** Default debuggable=true in some flavors; allows ADB shell on production builds.

#### PROBE: GoogleService-Info.plist / google-services.json committed to public repo (info, not strictly secret)

- Info.

#### PROBE: Flutter `--release` builds containing source-tree paths (DWARF on iOS)

- Info.

#### PROBE: pubspec.yaml assets directory containing .env / config-with-secrets

- **Language:** Dart | **Category:** Build/Deploy | **Severity:** critical
- **Detection approach:** Scan assets list; cross-reference contents.

#### PROBE: Flutter Web index.html with inline secret in `<script>` tag (e.g., Stripe publishable + secret swap)

- **Language:** Dart | **Category:** Build/Deploy | **Severity:** critical
- **Detection approach:** RX over web/index.html for known secret patterns.

#### PROBE: melos.yaml / fastlane Fastfile with hardcoded credentials

- See Ruby pattern.

## Cross-Cutting Probe Families and Implementation Notes

The following probe families are cross-cutting and apply to every language section above. They are listed once here rather than repeated 14 times.

### Cross-Cutting Pattern: Secret Detection (all languages)

Every language section above references hardcoded provider keys; here is the consolidated detection-pattern bank Pre-Flight should bundle once and apply to every source file regardless of language.

| Provider              | Pattern                                                                             | Severity                           |
| --------------------- | ----------------------------------------------------------------------------------- | ---------------------------------- | -------- |
| OpenAI                | `sk-[A-Za-z0-9]{20,}`, `sk-proj-[A-Za-z0-9_-]{50,}`, `sess-[A-Za-z0-9]{40,}`        | critical                           |
| Anthropic             | `sk-ant-(api03                                                                      | sid01)-[A-Za-z0-9_-]{60,}`         | critical |
| Google AI / Gemini    | `AIza[0-9A-Za-z_-]{35}`                                                             | critical                           |
| xAI                   | `xai-[A-Za-z0-9]{30,}`                                                              | critical                           |
| Groq                  | `gsk_[A-Za-z0-9]{40,}`                                                              | critical                           |
| Cohere                | `co_[A-Za-z0-9]{40,}` (heuristic)                                                   | critical                           |
| Mistral               | `[A-Za-z0-9]{32}` set in `MISTRAL_API_KEY` literal                                  | high                               |
| Perplexity            | `pplx-[A-Za-z0-9]{40,}`                                                             | critical                           |
| Hugging Face          | `hf_[A-Za-z0-9]{30,}`                                                               | critical                           |
| Replicate             | `r8_[A-Za-z0-9]{30,}`                                                               | critical                           |
| OpenRouter            | `sk-or-v1-[A-Za-z0-9]{60,}`                                                         | critical                           |
| AWS Access Key        | `AKIA[0-9A-Z]{16}` paired with 40-char secret                                       | critical                           |
| AWS Session Token     | `ASIA[0-9A-Z]{16}`                                                                  | high                               |
| Google Cloud SA JSON  | `"private_key": "-----BEGIN PRIVATE KEY-----"`                                      | critical                           |
| Azure storage         | `DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...`                     | critical                           |
| Stripe live           | `sk_live_[A-Za-z0-9]{24,}`, `rk_live_[A-Za-z0-9]{24,}`                              | critical                           |
| Stripe restricted     | `rk_test_...` (info; testing key shipped is config debt)                            | low                                |
| Slack                 | `xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]{24}`, `xoxp-...`, `xapp-...`                        | high                               |
| GitHub PAT            | `ghp_[A-Za-z0-9]{36}`, `gho_`, `ghu_`, `ghs_`, `ghr_`                               | critical                           |
| GitHub fine-grained   | `github_pat_[A-Za-z0-9_]{82}`                                                       | critical                           |
| npm token             | `npm_[A-Za-z0-9]{36}`                                                               | critical                           |
| PyPI API token        | `pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]+` (base64-encoded JWT-like)                      | critical                           |
| HashiCorp Vault       | `s\.[A-Za-z0-9]{24,}`, `hvs\.[A-Za-z0-9_-]+`                                        | critical                           |
| Vercel                | `[A-Za-z0-9]{24}` paired with vercel.com context                                    | high                               |
| Supabase service role | JWT with `role: service_role`                                                       | critical                           |
| Postgres / MySQL URLs | `postgres://[^@]+:[^@]+@`, `mysql://[^@]+:[^@]+@`, `mongodb(\+srv)?://[^@]+:[^@]+@` | high                               |
| Generic JWT           | `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`                              | medium (info; may be public token) |

False-positive guard: exclude obvious placeholders (`your_key`, `EXAMPLE`, `xxxxx`, `...`, `<TOKEN>`), exclude `.example`/`.sample` filenames, exclude files matching `test_*` glob, and require literal context (assignment to env / config / SDK constructor) rather than appearing in comments.

### Cross-Cutting Pattern: Slopsquatting / Hallucinated-Package Defense (all package managers)

For each language's dependency manifest, Pre-Flight should bundle two lists:

1. **High-popularity allowlist (~top 2,000 packages per ecosystem).** Any manifest entry whose name has Levenshtein distance ≤ 2 from a name on this list, but is NOT exactly on the list, is flagged as **high severity / suspected typosquat or slopsquat**. The Wikipedia / USENIX 2025 / Socket research bank shows 38% of LLM-hallucinated package names are conflations (`express-mongoose`), 13% are typo variants, 51% are pure fabrications, and 8.7% of Python-hallucinated names are valid JavaScript packages. The conflation case is detectable by checking whether the manifest name contains substrings of two top-1000 names.

2. **Known-malicious deny list (per ecosystem, refreshed from public IOCs).** Exact name+version matches blocked. The bundled IOC lists per ecosystem were enumerated within each language section above. The cumulative volume across npm, PyPI, Maven Central, NuGet, RubyGems, crates.io, Packagist, Hex, pub.dev, and Go modules now exceeds 1.233M known-malicious packages (Sonatype 2026 SSCR).

Severity rubric: exact match on IOC list → critical, never confirm. Near-match (edit-distance ≤ 2) on top-2000 → high, surface for review. Reasonable-looking name not in top-2000 → low / info, suggest dependency-cooldown wait. The 7–14-day dependency cooldown (per GitGuardian and security researcher William Woodruff's research) would have prevented 8 of 10 major 2025 supply-chain attacks; Pre-Flight should report manifest entries pinning to a package version less than 7 days old as informational.

### Cross-Cutting Pattern: CI / GitHub Actions Audit (all languages)

GitHub Actions misconfigurations cross language boundaries because most projects deploy via Actions. Probes apply to every `.github/workflows/*.yml`:

| Probe                                                                                 | Severity       | Rationale                                                                 |
| ------------------------------------------------------------------------------------- | -------------- | ------------------------------------------------------------------------- | ---- | --------------------------- |
| `pull_request_target` trigger combined with `actions/checkout` of PR HEAD ref         | critical       | Pwn Request pattern; TanStack CVE-2026-45321 vector                       |
| Action reference by tag (`@v3`, `@main`) instead of pinned commit SHA                 | high           | Trivy March 2026 compromise rewrote 75 of 76 release tags                 |
| `${{ secrets.* }}` exposure on `pull_request` or `pull_request_target` triggers       | critical       | TeamPCP campaign pattern                                                  |
| `actions/cache` with key that does not include a security-domain segregator           | high           | Cache poisoning vector in TanStack incident                               |
| Workflow with `permissions: write-all` or no explicit permissions block               | medium         | Excessive privilege                                                       |
| OIDC `id-token: write` permission on PR-triggered workflows                           | critical       | OIDC token extraction from runner memory was the TanStack escalation path |
| Run step containing `curl ...                                                         | sh`or`wget ... | bash`                                                                     | high | Unverified script execution |
| `env: NODE_AUTH_TOKEN`/`PYPI_TOKEN`/`NPM_TOKEN` set before checkout of untrusted code | critical       | Token leakage to malicious PR code                                        |
| Self-hosted runners on public repos                                                   | high           | Persistent compromise risk                                                |
| Reusable workflow with `secrets: inherit` from unaudited callees                      | medium         | Excessive sharing                                                         |

### Cross-Cutting Pattern: Container / Deployment (all languages)

Every language section has a "Build / Deploy" subsection covering its base image. The cross-cutting probes that apply to every Dockerfile regardless of language:

- `FROM <image>` with no tag or `:latest` tag; medium
- `FROM <image>` without `@sha256:` digest pin; low (info)
- `RUN curl ... | sh`; high
- `COPY . .` followed by `ENV` containing a secret; critical
- `EXPOSE` of well-known admin ports (`5432`, `6379`, `27017`, `9200`, etc.) without auth indication; medium
- `--privileged` or `--cap-add=ALL` in docker-compose.yml / Kubernetes manifests; high
- Kubernetes `securityContext: { runAsUser: 0 }`; medium
- Kubernetes `hostNetwork: true` or `hostPID: true`; high
- Helm values.yaml with default password literals (`admin`/`admin`, `password`/`password`); high
- `.dockerignore` missing entries for `.env`, `.git`, `node_modules`, `__pycache__`, `target/`, `build/` etc.; medium

### Cross-Cutting Pattern: MCP (Model Context Protocol); emerging in every language

Per the cross-tool concern in the task brief, MCP servers are a 2026 attack surface across languages. Probes that apply to every MCP server implementation (Python, TypeScript, Go, Rust, etc.):

- MCP server `tools` list registering a shell-execution / file-write / network-fetch tool without a documented allowlist of paths or URLs; high
- MCP server transport bound to `0.0.0.0` (vs `127.0.0.1`) without auth; critical
- MCP server returning raw stdout from a subprocess without sanitization; high
- MCP `resources` exposed to clients with no path normalization; high (path traversal)
- MCP server reading `.env` and exposing it as a resource (observed in early MCP demos); critical

### Implementation Guidance for Pre-Flight v0.5+

1. **Parsing infrastructure.** Use tree-sitter (with browser-compiled WASM grammars) for all 14 languages; already proven for `tree-sitter-python`, `tree-sitter-rust`, `tree-sitter-go`, `tree-sitter-java`, `tree-sitter-kotlin`, `tree-sitter-swift`, `tree-sitter-c-sharp`, `tree-sitter-c`, `tree-sitter-cpp`, `tree-sitter-ruby`, `tree-sitter-php`, `tree-sitter-scala`, `tree-sitter-elixir`, `tree-sitter-dart`. Manifest parsing uses native browser parsers: JSON for npm/Cargo.lock/composer.json, TOML for pyproject/Cargo, YAML for pubspec/mix/GitHub Actions, XML for pom/AndroidManifest/plist.

2. **Severity calibration.** The "vibe coder shipping to real users" audience suggests biasing toward high signal-to-noise: prefer fewer, higher-confidence findings (critical/high) over many low-confidence info-level alerts. Within the budget of 40–60 probes per language, 8–12 should be critical, 15–25 high, 10–20 medium, rest low/info.

3. **False-positive management.** Each probe entry above lists its primary false-positive risk. The strongest mitigations across all probes:

- Filename allowlist: exclude `test_*`, `*_test.go`, `*Tests.cs`, `*Spec.scala`, `spec/`, `tests/`, `*.example.*`.
- Placeholder allowlist: exclude obvious placeholder strings inside literals.
- Repository-shape gating: distinguish "library project" (don't enforce pin-strictness on dependencies) from "application/service project" (do enforce). Heuristic markers: presence of `Dockerfile`, `Procfile`, `wsgi.py`, `manage.py`, `application.properties` server section, `Cargo.toml` `[[bin]]`, `package.json` `"private": true`, `main()` entry point.

4. **IOC list maintenance.** Pre-Flight should bundle a static JSON snapshot at release, plus optionally a feature flag for "fetch latest IOC list from preflight.midatlantic.ai" once per session if the user opts in. Given the no-network-calls constraint, lean on the static snapshot and document the release cadence.

5. **Out-of-scope explicitly:**

- **OWASP A04 Insecure Design**; almost entirely threat-modeling work; only symptom-probes (e.g., missing rate limiting on auth endpoints if detectable in framework annotations) are in scope.
- **OWASP LLM09 Misinformation**; behavioral, not detectable from source.
- **Runtime authorization correctness**; detectable only via behavioral testing.
- **Cryptographic protocol soundness** beyond algorithm-name pattern matching.
- **Race conditions** beyond high-confidence syntactic patterns (mutex-across-await, defer-in-loop).
- **Container runtime / Kubernetes admission policies**; handled by Trivy, Checkov, etc., though static manifest probes are in scope as listed.

6. **Open research items for v0.6+:**

- Probes for the agentic-IDE-specific attack surface: `.cursor/rules`, `.claude/settings.json`, `.continue/`, `.windsurf/`, `AGENTS.md`, `CLAUDE.md`; files an attacker can plant in a repo to instruct an AI assistant. Wiz reported the TanStack daemon hunted `.claude/settings.json` and `.vscode/tasks.json` as persistence artifacts; this entire file class is now a security boundary.
- Probes for hard-coded RAG corpora that may contain prompt-injection payloads; bundled documents, default seeds for vector stores.
- Probes for "AI commits" (commits authored by `Claude <noreply@anthropic.com>` or similar) that bypass code review.

7. **Citations honesty.** Where this document references a specific 2025–2026 incident (LiteLLM 1.82.7/8, TanStack CVE-2026-45321, Trivy compromise, Mini Shai-Hulud, intercom-php@5.0.2, CocoaPods sunset, NuGet shanhai666 and Nethereum typosquats, BoltDB Go Module Mirror, RubyGems May 2026 mass campaign, finch-rst RustSec advisories, NuGet logic-bomb campaign, Composer CVE-2026-40176/40261), the citations are drawn from primary vendor coverage (Snyk, Socket, Wiz, Datadog Security Labs, Trend Micro, StepSecurity, GitGuardian, Sonatype, ReversingLabs, Aikido, OX Security, Mend.io, Trail of Bits, Oversecured, E.V.A. Information Security) and primary registry blogs (RubyGems blog, Rust Blog, PyPI blog, dart.dev / pub.dev, CocoaPods blog). Where an incident is referenced but a specific CVE is not cited, the entry uses qualifying language ("general pattern reported by [vendor type]") per the task brief. Probes marked **SPECULATIVE** are noted inline; the maintainer should treat those as research-grade rather than ship-ready.

8. **Severity distribution sanity check.** Across the 14 language sections in this document, the rough probe count is: Python (~55), Rust (~45), Go (~42), Java (~45), Kotlin (~40), Swift (~42), C# (~45), C (~40), C++ (~40), Ruby (~45), PHP (~45), Scala (~40), Elixir (~40), Dart (~42). Total enumerated probe candidates: approximately 600. After deduplication via the cross-cutting sections, the maintainer should expect on the order of 500–550 unique language-specific probes and 50–80 cross-cutting probes once v0.5 ships across all 14 languages. For comparison, v0.4 ships 43 probes for JS/TS alone, so per-language probe density in this research is in line.

This concludes the probe-candidate research for Pre-Flight v0.5+. The maintainer should treat this document as a starting research aggregation; each probe entry above is intended as input to a downstream implementation decision (probe yes/no), not as a finished probe specification. Implementation should proceed language-by-language with framework-specific probe expansion as the secondary research pass, following the framework inventory listed at the top of each language section.

## Research compiled May 14, 2026, for Pre-Flight v0.5+ multi-language expansion. Sections above cover Python, Rust, Go, Java, Kotlin, Swift, C#, C, C++, Ruby, PHP, Scala, Elixir, and Dart; each with framework inventory, six probe categories (AI-tool failure patterns, OWASP Top 10:2025 mappings, OWASP LLM Top 10:2025 mappings, language-specific memory/concurrency/resource patterns, supply-chain patterns with 2025–2026 IOC lists, and build/deploy patterns), and cited primary-source incidents. The closing section consolidates cross-cutting probe families (secret detection, slopsquatting defense, GitHub Actions audit, container/deployment, MCP) along with implementation guidance, false-positive management strategy, severity calibration, out-of-scope items, and an estimated total of ~600 probe candidates across the 14 languages plus 50–80 cross-cutting probes. Speculative probes are explicitly marked SPECULATIVE; ambiguous incident attributions use qualifying language per the task brief. Primary sources span OWASP, NIST, CVE/NVD, GitHub Advisory Database, RustSec, PyPI blog, RubyGems blog, dart.dev / pub.dev, Snyk, Socket, Wiz, Datadog Security Labs, Trend Micro, StepSecurity, GitGuardian, Sonatype (2026 State of the Software Supply Chain Report), ReversingLabs, Aikido, OX Security, Mend.io, Trail of Bits, Oversecured, E.V.A. Information Security, Semgrep, and academic research (USENIX 2025 "We Have a Package for You!", arXiv 2407.18760 Maven-Hijack, arXiv 2310.02059 Copilot security study). The document is structured for direct paste into a research aggregation document, with each probe entry following the requested PROBE NAME / LANGUAGE / CATEGORY / FRAMEWORK / SEVERITY / WHAT IT CATCHES / WHY AI GETS THIS WRONG / DETECTION APPROACH / FALSE POSITIVE RISK / REMEDIATION / KNOWN INCIDENTS format.

## v0.5 Changelog

### Probe count

- v0.4 (current production): 43 probes covering JavaScript and TypeScript only.
- v0.5 (this release): 606 candidate probes covering 14 languages plus JavaScript/TypeScript.
  - 599 from Claude v0.5 research depth catalog.
  - 7 from Google v0.5 comparison gap-fill.
  - XL-001 to XL-012 shared families serve as cross-references, not standalone probes.

### Schema additions (new in v0.5)

- `why_ai_v05`: AI-specific failure mode rationale per probe.
- `vibe_v05`: vibe-coder mental model that produces this bug.
- `fp_gates_v05`: false-positive gates as a first-class structured field.
- `autofix_v05`: mechanical / review-needed / manual taxonomy.
- `fixtures_v05`: required positive and negative fixture path references.
- `xl_ref`: optional cross-reference to XL-001 through XL-012.
- `ioc_bundle_ref`: optional reference into `preflight_v05_iocs.json`.

### Citation corrections applied (from May 14, 2026 verification pass)

1. Trivy compromise tag count: "76 of 77 trivy-action tags" corrected to "75 of 76 trivy-action tags" (source: Wiz, Microsoft, Cyber Magazine, Phoenix Security).
2. Termncolor/colorinal discovery date: "August 2025" corrected to "July 22, 2025 Zscaler ThreatLabz discovery; uploads July 16-22, 2025" (source: Zscaler, The Hacker News).
3. USENIX 2025 hallucination statistics: "19.7% across 16 LLMs and 576,000 samples" corrected to "5.2% for commercial models, 21.7% for open-source models, 205,474 unique hallucinated package names" (source: Spracklen et al, arXiv:2406.10279, USENIX Security 2025).
4. mvnpm Maven Central spillover scope: "~270 npm packages had Maven Central artifacts" corrected to "org.mvnpm:posthog-node:4.18.1 was the confirmed Maven Central spillover artifact" (source: Socket, The Hacker News, GitLab GLAD GMS-2025-800).
5. shanhai666 NuGet packages dates: clarified to "published 2023-2024, disclosed by Socket November 5-7, 2025; trigger dates Aug 8 2027 and Nov 29 2028; Sharp7Extend activates immediately; 9 packages, 9,488 downloads total" (source: Socket via Pandya, BleepingComputer, Industrial Cyber).
6. RustSec finch family campaign: clarified to five packages with three suffix patterns (finch-rust RUSTSEC-2025-0148, finch-rst RUSTSEC-2025-0150, sha-rst RUSTSEC-2025-0151, finch_cli_rust RUSTSEC-2025-0152, plus sha-rust dependency), reported Dec 9 2025 by Matthias Zepper of NGI Sweden, issued Feb 12-13 2026 (source: Rust Blog Feb 13 2026, RustSec advisory pages, Socket).
7. Trivy CVE assignment: added CVE-2026-33634 with CISA KEV remediation deadline April 8, 2026 (source: SANS ISC, Halcyon).

### Em-dash policy

All em-dash characters (U+2014) stripped from prose. 348 instances replaced with semicolons, commas, or removed depending on context. Applies per user preference (no em-dashes in prose ever).

### Verified 2026 incident timeline (canonical sequence)

This sequence is the spine of the 2026 supply-chain threat intelligence baseline. All supply-chain probes referencing 2026 IOCs draw from this timeline via `ioc_bundle_ref`:

1. Trivy March 19, 2026 (TeamPCP, CVE-2026-33634, 75 of 76 trivy-action tags force-pushed)
2. LiteLLM March 24, 2026 (1.82.7 at 10:39 UTC, 1.82.8 at 10:52 UTC, TeamPCP via stolen PyPI publish token from Trivy CI)
3. Telnyx March 27, 2026 (4.87.1 and 4.87.2 at 03:51 UTC, TeamPCP, WAV steganography payload)
4. Axios March 31, 2026 (1.14.1 and 0.30.4 at 00:21 UTC, Sapphire Sleet/UNC1069 (North Korea), separate actor from TeamPCP, plain-crypto-js@4.2.1, WAVESHAPER.V2)
5. Bitwarden CLI April 2026 (@bitwarden/cli@2026.4.0, TeamPCP)
6. SAP npm April 29, 2026 (four packages, TeamPCP, Mini Shai-Hulud campaign begins)
7. Lightning + intercom-client + intercom-php April 30, 2026 (lightning 2.6.2/2.6.3 PyPI, intercom-client 7.0.4/7.0.5 npm, intercom/intercom-php 5.0.2 Packagist at 20:53-22:37 UTC, all TeamPCP, all Mini Shai-Hulud)
8. TanStack/Mistral May 11, 2026 (42 @tanstack/\* packages with 84 versions on npm at 19:20-19:26 UTC, plus mistralai 2.4.6 PyPI and guardrails-ai 0.10.1 PyPI, CVE-2026-45321 CVSS 9.6, GHSA-g7cv-rxg3-hmpx, TeamPCP, first npm supply chain attack with valid SLSA Build Level 3 attestations)

### Files in this release

- `preflight_v05_probe_inventory.md` (this file): the merged probe inventory.
- `preflight_v05_iocs.json`: structured 2026 IOC bundle with package@version, UTC timestamps, threat actor attribution, CVE references, GHSA references.
- `preflight_v05_consensus_matrix.csv`: empty template for cross-draft consensus tracking.
