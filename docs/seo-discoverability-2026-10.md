# Discoverability: where PreFlight stands in search, and what to do about it

Written 2026-10-28. Companion to `docs/plan-finish-2026-10.md` item 13. Every claim below was checked the same day against a live search or a live fetch; the queries are listed so they can be rerun.

Outside tools and competing scanners are named in this document because it is research. None of them may appear in product copy, the README, llms.txt or a commit subject.

## 1. The site is not in the index

| Check                                        | Result                                                                                           |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Bing, `site:preflight.midatlantic.ai`        | Zero results on the domain. Bing padded the page with unrelated results.                         |
| Two general web searches for the domain name | Zero results on the domain. Only unrelated "preflight" aviation and Adobe products.              |
| Live `robots.txt`                            | Allows every crawler, names 14 AI crawlers as allowed, points to the sitemap. Not the problem.   |
| Live `sitemap.xml`                           | 100 URLs, newest `lastmod` 2026-08-27. Stale because `prebuild` never ran (fixed in `384b9c3`).  |
| Google Search Console verification file      | Shipped in May. The May handoff's "John clicks Verify and submits the sitemap" never happened.   |
| Live homepage                                | Renders fully server-side, title "PreFlight — Educational Audit for Vibers Building Vibeware".   |
| Third-party mentions                         | One registry listing (TomeVault, "Silver tier, clean"). No other page on the web links the site. |

Nothing else in this document matters until this is fixed. A page that is not indexed does not rank for anything, and every landing page written before then is written into a void.

### What fixes it

1. **John, Google Search Console.** Verify the property (the HTML file method is already deployed), submit `https://preflight.midatlantic.ai/sitemap.xml`, and request indexing for the homepage and `/learn/`. Then watch the Coverage report for a week.
2. **John, Bing Webmaster Tools.** Import the verified GSC property (one click once GSC exists), or verify directly. Bing feeds Copilot and ChatGPT search, which is where vibe coders ask questions.
3. **Repo, IndexNow.** Added today: `scripts/indexnow.mjs` pings every sitemap URL to Bing, Yandex, Seznam and through Bing the AI search engines, on every push to `main`. Google ignores IndexNow; that is what step 1 is for. The key file at `public/<key>.txt` is public by design: the key proves control of the host, it is not a secret.
4. **Push.** The live sitemap is two months stale and missing seventeen pages. The nine local commits carry the fix and the pages.
5. **Links.** The site has no inbound links. Search engines treat a page nobody links to as a page nobody wants. Section 5 lists where the competing scanners got theirs.

## 2. What people type, and who answers

Each row is a query shape seen ranking, with who holds it today and whether PreFlight has a page that could.

| Query shape                                                        | Who ranks today                                                                               | PreFlight page today                    | Verdict                                                                                           |
| ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------- | --------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `free security scanner for vibe coded apps`                        | Launch listings (hunted.space, Product Hunt, PeerPush), VibeCheck, SecureMyVibes, Nullsec     | none                                    | Crowded with URL scanners. PreFlight is the only source-level, in-browser, no-upload one; say so. |
| `is my lovable / bolt / cursor / replit app secure`                | unpwned.io, vibeappscanner.com, vibe-eval.com, each with one page per platform per question   | none                                    | Programmatic Q&A. Five platforms times four questions, written once, ranks.                       |
| `{platform} security checklist`                                    | Same three vendors, Replit's own docs, Cleveroad, Fingerprint                                 | none                                    | One checklist page per platform, each linking the matching probes and Learn patterns.             |
| `vibe coding security checklist`                                   | Replit docs, Cloud Security Alliance, BSS Commerce, Retool, Fingerprint                       | none                                    | High volume, generic, hard. Worth one strong page because the Learn library backs it.             |
| `supabase rls checker`                                             | hand-dot extension, vibe-eval, SupaShield CLI, Supabase's own tester, GuardLayer (static SQL) | Supabase RLS probe, no entry page       | GuardLayer ranks with exactly PreFlight's mechanism (paste SQL, browser, no upload). Open.        |
| `cursor rules file backdoor check` / `.cursorrules security`       | Checklists only. No tool found by the search.                                                 | AI Rules Files probe, no entry page     | **Open.** PreFlight has had this probe since spring and nobody can find it.                       |
| `AGENTS.md security` / `CLAUDE.md malicious instructions scanner`  | Three CLIs (Skillgate, AgentShield, agentscanner), research blogs, NVIDIA red team            | AI Rules Files probe, new field report  | Open for a browser tool. The field report is the hook; it needs an entry page.                    |
| `mcp server security scanner`                                      | Four CLIs on PyPI and npm, one browser URL checker                                            | MCP Security probe, no entry page       | Open for config-file scanning in the browser.                                                     |
| `php2shell check my php version`                                   | OpenAI's checker (reads the served version), Astra's web checker, distro guides               | PHP Runtime Version probe, field report | The "in your repos" angle has one Medium post. PreFlight reads the Dockerfile. Open.              |
| `open source security scanner AI generated code browser no upload` | **Nothing found.** The search returned CLIs and hosted tools and said so.                     | the whole product                       | This is the unoccupied square. The homepage title does not contain one of these words.            |
| `security audit my claude code project free`                       | Claude Code skills in registries, DevAudit CLI                                                | none                                    | A "scan before you ship" page for agent users; Copy Agent Prompt is the hook.                     |

Two things the table shows. First, the competing scanners rank on volume of small pages, not on one good one: unpwned.io alone has a page for every platform times every question a worried builder types. Second, the queries where PreFlight already has the probe and nobody has the page (rules files, AGENTS.md, MCP config, php2shell in the repo, RLS from SQL) are the cheapest ground on the web right now.

### A name collision

A different tool called PreFlight ("a local AST-based security gate that guards your codebase against AI hallucinations") launched on Product Hunt as `preflight-5`, in the same niche. Searches for "PreFlight security AI code" will split between the two. The fix is not a rename; it is being the one that is indexed, linked and described consistently as "PreFlight by Mid-Atlantic AI, free, in-browser, open source". Every listing in section 5 should use that phrase.

## 3. The homepage and the words it does not contain

Live title: `PreFlight — Educational Audit for Vibers Building Vibeware`. H1: the same line. Neither contains "security", "scanner", "free", "AI-generated", "vibe coding", "open source" or "in-browser", which are the words every query in section 2 is made of. The brand line is John's and stays; the question is what sits beside it in the `<title>` and in the first sentence of the page.

Recommended, for John to accept or rewrite:

- `<title>`: `PreFlight: free in-browser security scanner for AI-built apps | Mid-Atlantic AI`
- H1 stays as John's line; the sentence under it carries the search words: "A free, open-source security audit for vibe-coded apps. Runs in your browser, your code never leaves the tab, 131 probes, no signup."
- Meta description cut to its first sentence (about 160 characters). The current one runs about 700 characters and engines truncate it mid-sentence.

The `og:description` already carries the slogan and can stay.

## 4. Pages to write, in order of return

Each is a short entry page in the style of `/owasp-llm-2026`: one query answered plainly, the matching probes named, the matching Learn patterns and field reports linked, the scanner one click away. Demi's register for the body, John's for any first-person line. No competing tool named.

| #   | Route                                                                  | Target query                                               | Backed by                                                              |
| --- | ---------------------------------------------------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------- |
| 1   | `/check/cursor-rules`                                                  | cursor rules file backdoor, .cursorrules security          | AI Rules Files, Agent Config Backdoor; rules-file incidents            |
| 2   | `/check/agents-md`                                                     | AGENTS.md security, CLAUDE.md malicious instructions       | same probes; the Downloads-folder field report                         |
| 3   | `/check/mcp-config`                                                    | mcp server security scanner, mcp config audit              | MCP Security; MCP incidents                                            |
| 4   | `/check/supabase-rls`                                                  | supabase rls checker                                       | Supabase RLS; the 16,326-table study                                   |
| 5   | `/check/php2shell`                                                     | php2shell check, php version vulnerable                    | PHP Runtime Version; the php2shell field report                        |
| 6   | `/check/lovable`, `/bolt`, `/cursor`, `/replit`, `/v0`, `/claude-code` | is my {platform} app secure, {platform} security checklist | the probe set that matches each platform's defaults; the pattern pages |
| 7   | `/vibe-coding-security-checklist`                                      | vibe coding security checklist                             | the Learn library, ordered as a checklist                              |
| 8   | `/free-security-scanner-ai-generated-code`                             | the unoccupied square                                      | the homepage, said in the words people search                          |

Pages 1 to 5 are one session: the probes and the content exist, the pages are glue. Page 6 is the programmatic set the competitors rank on; one template, six platforms, each with the four question headings ("is it secure", "can it be hacked", "what to check before publishing", "what PreFlight finds"). Pages 7 and 8 are the hard ones and come last.

## 5. Getting it in front of people

Search is slow and needs links. The scanners that rank today got their first links from launch directories, all free, all one form each. John's call on every one, because each is a public listing in his name:

- Product Hunt, hunted.space, PeerPush, StackShare, AlternativeTo, Saasworthy. Every competing scanner in section 2 is on at least three of these.
- GitHub: topics on the repository (`security`, `sast`, `vibe-coding`, `ai-generated-code`, `supabase`, `static-analysis`), a `SECURITY.md` and `CONTRIBUTING.md` (the September landscape note already flagged their absence), and pull requests to the awesome lists (`awesome-vibe-coding`, `awesome-ai-security`, `awesome-sast`).
- Show HN, r/vibecoding, r/webdev, the two Facebook groups the May launch used. The hook is the one sentence no other tool can say: open source, in the browser, the code never leaves the tab, nothing to sign up for.
- The field reports as posts. Five went in today; each is a post in John's voice through the content pipeline (`/forge`, `/gate`), pointing at the report, not at the homepage.
- The "what's actually free" series on midatlantic.ai from the September landscape work, which is where competitor names are allowed.

## 6. Answer engines

ChatGPT search, Copilot and Perplexity pull from Bing's index plus their own crawl. The site allows all of their crawlers, ships `llms.txt`, and prerenders every route, so the mechanics are right. What they lack is the same thing search lacks: pages shaped like the questions people ask them. Pages 1 to 6 above are those pages. Once Bing indexes the site, the answer engines follow within days; today they have nothing to cite.

## 7. What changed in the repo today for this

- `scripts/gen-sitemap.mjs` now runs inside `npm run build` (sitemap was stale on the live site since August).
- `scripts/indexnow.mjs`, the key file, an `indexnow` npm script and a non-fatal CI step on pushes to `main`.
- Counts and the share card say 131.
- Field reports featured on the homepage.

Everything in sections 3 to 5 is John's copy or John's name and is not done.

## Queries run, for rerunning

`free security scanner for vibe coded apps`; `lovable app security audit scan`; `supabase rls checker tool`; `site:preflight.midatlantic.ai`; `"preflight.midatlantic.ai"`; `vibe coding security checklist`; `AGENTS.md security risk prompt injection rules file`; `is my bolt.new cursor app secure how to check`; `php2shell check my php version vulnerable`; `best free static analysis tool AI generated code 2026 no signup browser`; `cursor rules file security scanner .cursorrules backdoor check`; `mcp server security scanner free config audit`; `security audit my claude code project before deploy free tool`; `open source security scanner for AI generated code runs in browser no upload`; `github midatlanticAI PreFlight security audit vibe coding`; `is my replit app secure before publishing how to check`; `v0 vercel windsurf base44 app security check vulnerabilities`; `AGENTS.md CLAUDE.md scanner detect malicious instructions tool`.
