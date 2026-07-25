# Mid-Atlantic AI brand kit

A single reference another person or tool can be pointed at. Assembled from the
live implementation in this repo, the marketing site, and the original brand
resource documents.

**Canonical source of truth for anything shipped in code:**
[`src/lib/theme.js`](../src/lib/theme.js). That file wins over this document if
they ever disagree, because it is what actually renders.

---

## Colors

The palette comes from the logo: a navy robot with orange antenna lights and
mint-cyan eyes.

| Role                | Hex       | Where it comes from                      |
| ------------------- | --------- | ---------------------------------------- |
| **Background navy** | `#0a1226` | Darkened logo navy, chosen for contrast  |
| **Logo navy**       | `#1b2d52` | The robot's body. Chrome accents         |
| **Orange**          | `#f26b1f` | The antenna lights. Primary accent, CTAs |
| **Mint cyan**       | `#9fe5dd` | The robot's eyes. Friendly highlights    |
| **Text**            | `#f5f7fa` | Near-white on navy                       |

**Two navies, and they are not interchangeable.** `#1b2d52` is the real logo
navy. `#0a1226` is a deliberately darkened variant used as the app background so
body text clears WCAG contrast against it. Use the logo navy for anything
logo-adjacent or print; use the darker one behind text.

### Surfaces and text

| Token        | Hex       | Contrast on background | Level    |
| ------------ | --------- | ---------------------- | -------- |
| `panel`      | `#11192e` | surface                | —        |
| `panelAlt`   | `#172143` | surface                | —        |
| `panelHover` | `#1d294d` | surface                | —        |
| `border`     | `#1f2a44` | surface                | —        |
| `borderAlt`  | `#2c3a5e` | surface                | —        |
| `text`       | `#f5f7fa` | 17.7:1                 | AAA      |
| `textDim`    | `#a8b1c5` | 8.94:1                 | AAA      |
| `textMuted`  | `#8a96b0` | 6.5:1                  | AA       |
| `accent`     | `#f26b1f` | 6.18:1                 | AA Large |
| `accentDim`  | `#c2541a` | —                      | —        |

Every ratio above is measured against `#0a1226`. `textMuted` was raised from
`#6b7693`, which measured 4.15:1 and failed AA. Do not lower these without
re-measuring.

### Severity scale

Each severity is a background, foreground, border and glow. Severity is never
communicated by color alone.

| Severity   | Foreground | Background | Border    |
| ---------- | ---------- | ---------- | --------- |
| `critical` | `#fb7185`  | `#1f0e1a`  | `#7f1d1d` |
| `high`     | `#f97316`  | `#1f140a`  | `#9a3412` |
| `medium`   | `#fbbf24`  | `#1f1a0a`  | `#854d0e` |
| `low`      | `#60a5fa`  | `#0e1a30`  | `#1e3a8a` |
| `info`     | `#9fe5dd`  | `#0d1d2c`  | `#3b6e69` |

Success reuses the brand mint `#9fe5dd` rather than introducing a green.

### Category accents

`Data Breach` `#f97316` · `Code Injection` `#fbbf24` · `Supply Chain` `#a78bfa`
· `Auth & Access` `#fb7185` · `AI/LLM Security` `#9fe5dd` ·
`Misconfiguration` `#60a5fa`

---

## Typography

| Role          | Stack                                                          |
| ------------- | -------------------------------------------------------------- |
| **Display**   | Rubik, Helvetica Neue, Helvetica, Arial, sans-serif            |
| **Body / UI** | Roboto, Helvetica Neue, Helvetica, Arial, sans-serif           |
| **Condensed** | Roboto Condensed, Roboto, Helvetica Neue, Arial, sans-serif    |
| **Eyebrow**   | Impact, Haettenschweiler, Arial Narrow Bold, sans-serif        |
| **Mono**      | ui-monospace, SF Mono, Menlo, Consolas, Roboto Mono, monospace |

Impact is the eyebrow/kicker face only. It is not a headline font here.

---

## Logo and assets

| Asset              | Path                                     | Use                            |
| ------------------ | ---------------------------------------- | ------------------------------ |
| Logo (app)         | `public/maai-logo.svg`                   | In-app header, 336×192 viewBox |
| Favicon            | `public/favicon.svg`                     | Browser tab                    |
| Icon sprite        | `public/icons.svg`                       | UI icons                       |
| Social card        | `public/og-card.svg` → `og-card.png`     | Open Graph / Twitter           |
| Logo (bot mark)    | `~/midatlanticai-site/img/logo-bot.svg`  | Marketing site, mark only      |
| Logo (bot raster)  | `~/midatlanticai-site/img/logo-bot.png`  | Marketing site                 |
| Logo (full lockup) | `~/midatlanticai-site/img/logo-full.png` | Marketing site, full lockup    |

The social card is authored as SVG and rendered to PNG via `npm run og`
(requires the `sharp` native binary).

**Other brand sources, outside version control:**

- `~/Downloads/brand resource docs.pdf` — the original brand resource document.
- `~/midatlanticai-site/` — the marketing site, which is the reference for how
  the brand is applied outside the product.

Those two and this document overlap on purpose. They live in different places
and serve different jobs, so redundancy is the point.

---

## Voice

The full rules live in [`CLAUDE.md`](../CLAUDE.md) and the manifesto at
`src/learn/manifesto.md`. The short version, which applies to all copy:

- No em-dashes. Periods or commas.
- No marketing register: no "comprehensive", "best-in-class", "powerful",
  "robust", "enterprise-grade", "unlock", "leverage", "seamless".
- No fear marketing, no manufactured urgency.
- No wellness encouragement, no "you've got this".
- No hedging filler: no "it is worth noting", "at the end of the day".
- No competing security platforms named in public-facing copy. Cite OWASP,
  MITRE/CWE, CISA, vendor official docs, W3C, MDN, named research orgs.
- AI providers (OpenAI, Anthropic, Google, xAI, Mistral) are not competitors.
  Naming them in a provider list is fine.

Product names are camelCase compounds: **PreFlight**, **FlightSchool**. Not
"Pre-Flight".

Audience: people building real products from natural-language prompts. Capable
practitioners developing a security sensibility, not beginners being talked
down to.

---

## Accessibility rules that are part of the brand

These are not optional polish. They are why the palette has the values it has.

- WCAG 2.2 AA minimum on all text. Most tokens above clear AAA.
- Never communicate meaning by color alone. Severity carries a shape and a
  label as well as a color.
- Touch targets meet WCAG 2.5.5.
- Respect `prefers-reduced-motion`.
- Every measured ratio is recorded in `theme.js` beside its token. Keep it that
  way when adding colors.
