---
title: The Python shapes that ship broken
slug: python-security
type: pattern
last_updated: 2026-07-27
draft: false
related_probe_ids:
  - Python Security
sources:
  - title: OWASP Top 10 2021 A03 — Injection
    url: https://owasp.org/Top10/A03_2021-Injection/
  - title: CWE-78 — OS Command Injection
    url: https://cwe.mitre.org/data/definitions/78.html
  - title: CWE-22 — Path Traversal
    url: https://cwe.mitre.org/data/definitions/22.html
  - title: CWE-916 — Use of Password Hash With Insufficient Computational Effort
    url: https://cwe.mitre.org/data/definitions/916.html
  - title: Python docs — subprocess, "Security Considerations"
    url: https://docs.python.org/3/library/subprocess.html#security-considerations
  - title: Flask docs — Debug Mode
    url: https://flask.palletsprojects.com/en/stable/debugging/
  - title: OWASP Password Storage Cheat Sheet
    url: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
---

Python reads so much like English that dangerous code looks tidy. `os.system("ping -c1 " + host)` is a sentence. It is also a remote shell for whoever controls `host`.

These are the shapes that show up most often in generated Flask and Django code, what each one actually does, and the fix.

## A shell command built from a request value

```python
host = request.args.get("host")
os.system("ping -c1 " + host)
```

`os.system` hands the whole string to `/bin/sh`. The shell reads `;` and `` ` `` and `$()` as instructions, so a `host` of `x; cat /etc/passwd` runs two commands and the second one is not yours. Quoting the value does not help, because the attacker supplies quotes too.

The fix is not escaping. It is refusing to build a command line at all:

```python
subprocess.run(["ping", "-c1", host], shell=False)
```

A list has argument boundaries the shell never gets to reinterpret. `host` can only ever be one argument, whatever is in it. When a shell is genuinely required, `shlex.quote()` the value and validate it against an allowlist first.

`shell=True` is the same hazard wearing a newer name, and so are `os.popen`, `subprocess.getoutput`, and `commands.getoutput`.

## A path built from a request value

```python
return send_file("uploads/" + request.args.get("f"))
```

`../../etc/passwd` walks straight out of `uploads/`. So does an absolute path, and `os.path.join` makes that worse rather than better: given a second argument that starts with `/`, it discards the first entirely. `os.path.join("uploads", "/etc/passwd")` is `/etc/passwd`.

Resolve, then confirm the result is still where you meant:

```python
base = Path("uploads").resolve()
target = (base / name).resolve()
if not target.is_relative_to(base):
    abort(400)
```

`resolve()` collapses the `..` segments before the check, which is the order that matters.

## A password compared with `==`

```python
if user.password == request.form["password"]:
```

If this comparison works, the database holds the password in plain text, so anyone who reads the database has every account, and people reuse passwords across sites. The comparison is also not constant time, which leaks length and prefix information to anyone patient.

Store a hash and let the library verify it:

```python
bcrypt.checkpw(entered.encode(), stored)
```

## A password hashed with md5 or sha1

```python
hashlib.md5(password.encode()).hexdigest()
```

md5 and sha1 are not broken here because collisions exist. They are wrong here because they are fast, and speed is what an attacker with a stolen table wants. Commodity hardware tries billions of candidates a second.

Use a hash designed to be slow and salted: `bcrypt`, `argon2`, or `hashlib.scrypt`. Rehash on the next successful login rather than forcing a password reset on everybody.

The same call for a cache key or an ETag is fine. The question is always what the value protects.

## `eval` on anything a user sent

```python
return str(eval(request.args.get("expr")))
```

This is remote code execution, not an input-validation problem. `eval` runs what arrives, including `__import__("os").system(...)`. For arithmetic, `ast.literal_eval` evaluates literals and nothing else. For anything richer, parse the input into a structure you defined and dispatch on it.

## `debug=True` in production

```python
app.run(host="0.0.0.0", port=8000, debug=True)
```

Flask's debug mode serves the Werkzeug console when an exception escapes, and that console executes Python in the process. Django's `DEBUG = True` renders settings and recent queries into the error page.

Read the flag from the environment and default it to off, so enabling it in production takes a deliberate act:

```python
app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
```

## A credential assigned a literal

```python
app.secret_key = "sk_prod_8fJ2mNq7XvR4tLpZ"
```

A secret in source is in every clone, every fork, and the whole git history. Deleting the line later does not remove it from the repository, and a published repo should be assumed to have been scraped within minutes.

Read it from `os.environ` or a secret manager, and rotate the value that was committed. Treat it as public from the moment it landed.

## What this probe does not do

PreFlight's dataflow analysis is JavaScript and TypeScript only, so the Python checks see the request value at the call site or one line above it. A value that travels through several functions before it reaches `os.system` is not tracked, and a clean Python result is weaker evidence than a clean JavaScript one. Read the handlers that touch the filesystem, the shell, and the network yourself.
