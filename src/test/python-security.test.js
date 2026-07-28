/**
 * Python security probe.
 *
 * Python was scanned but barely examined: four v0.5 adapters and nothing else,
 * so this exact 41-line Flask app — SQL injection, os.system command
 * injection, send_file traversal, md5 password hashing, a plaintext password
 * comparison, a hardcoded secret key, eval on request data and debug=True —
 * came back with ZERO findings. That is the one output a scanner must never
 * produce, because the reader stops looking.
 *
 * The precision half matters as much: every safe idiom below is the FIX this
 * probe's remediation recommends, and recommending a fix that then gets
 * flagged is how a tool loses a user for good.
 */

import { describe, it, expect } from 'vitest';
import { probePythonSecurity } from '../lib/probes/python.js';

const f = (path, content) => ({ path, content });
const scan = (content, path = 'app/main.py') => probePythonSecurity([f(path, content)]) || [];

const VULNERABLE_FLASK = `from flask import Flask, request, send_file
import os, hashlib

app = Flask(__name__)
app.secret_key = "sk_prod_8fJ2mNq7XvR4tLpZ"

@app.route("/login", methods=["POST"])
def login():
    u = get_user(request.form["email"])
    if u and u.password == request.form["password"]:
        return "ok"
    return "no", 401

@app.route("/register", methods=["POST"])
def register():
    return hashlib.md5(request.form["password"].encode()).hexdigest()

@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c1 " + host)
    return "pinged"

@app.route("/download")
def download():
    return send_file("uploads/" + request.args.get("f"))

@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr")))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
`;

describe('probePythonSecurity — recall', () => {
  it('the realistic vulnerable Flask app is no longer silent', () => {
    const found = scan(VULNERABLE_FLASK);
    expect(found.length).toBeGreaterThanOrEqual(7);
    for (const cwe of ['CWE-78', 'CWE-22', 'CWE-95', 'CWE-916', 'CWE-261', 'CWE-798', 'CWE-489']) {
      expect(
        found.some((x) => x.cwe === cwe),
        `expected a ${cwe} finding`
      ).toBe(true);
    }
  });

  const shapes = [
    [
      'os.system with request data',
      'CWE-78',
      'import os\nfrom flask import request\ndef f():\n    os.system("ping " + request.args.get("h"))\n',
    ],
    [
      'one-hop through a variable',
      'CWE-78',
      'import os\nfrom flask import request\ndef f():\n    h = request.args.get("h")\n    os.system("ping " + h)\n',
    ],
    [
      'subprocess shell=True',
      'CWE-78',
      'import subprocess\ndef f(folder):\n    subprocess.run(f"tar -czf b.tgz {folder}", shell=True)\n',
    ],
    [
      'open() traversal',
      'CWE-22',
      'from flask import request\ndef f():\n    with open("docs/" + request.args.get("n")) as fh:\n        return fh.read()\n',
    ],
    [
      'requests SSRF',
      'CWE-918',
      'import requests\nfrom flask import request\ndef f():\n    return requests.get(request.args.get("url")).text\n',
    ],
    [
      'django request.GET',
      'CWE-918',
      'import requests\ndef f(request):\n    return requests.get(request.GET["url"]).text\n',
    ],
    [
      'eval on request data',
      'CWE-95',
      'from flask import request\ndef f():\n    return str(eval(request.args.get("expr")))\n',
    ],
    [
      'md5 on a password',
      'CWE-916',
      'import hashlib\ndef f(password):\n    return hashlib.md5(password.encode()).hexdigest()\n',
    ],
    [
      'plaintext comparison',
      'CWE-261',
      'from flask import request\ndef f(u):\n    if u.password == request.form["password"]:\n        return True\n',
    ],
    ['hardcoded credential', 'CWE-798', 'ADMIN_PASSWORD = "SuperSecret123!"\n'],
    ['django DEBUG', 'CWE-489', 'DEBUG = True\n'],
  ];
  for (const [name, cwe, src] of shapes) {
    it(`${name} fires ${cwe}`, () => {
      expect(scan(src).some((x) => x.cwe === cwe)).toBe(true);
    });
  }
});

describe('probePythonSecurity — precision', () => {
  const safe = [
    [
      'parameterised query',
      'def f(cur, x):\n    cur.execute("SELECT * FROM t WHERE a = %s", (x,))\n',
    ],
    [
      'subprocess list form, shell=False',
      'import subprocess\nfrom flask import request\ndef f():\n    host = request.args.get("h")\n    subprocess.run(["ping", "-c1", host], shell=False)\n',
    ],
    [
      'open with a fixed path',
      'def f():\n    with open("config/settings.yml") as fh:\n        return fh.read()\n',
    ],
    [
      'bcrypt.checkpw',
      'import bcrypt\ndef f(entered, stored):\n    return bcrypt.checkpw(entered, stored)\n',
    ],
    ['django check_password', 'def f(user, raw):\n    return user.check_password(raw)\n'],
    [
      'hmac.compare_digest',
      'import hmac\ndef f(a, password_hash):\n    return hmac.compare_digest(a, password_hash)\n',
    ],
    [
      'credential from the environment',
      'import os\nADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]\n',
    ],
    ['placeholder value', 'ADMIN_PASSWORD = "change-me"\n'],
    [
      'debug read from the environment',
      'import os\napp.run(debug=os.environ.get("DEBUG") == "1")\n',
    ],
    [
      'md5 for a cache key, not a password',
      'import hashlib\ndef cache_key(url):\n    return hashlib.md5(url.encode()).hexdigest()\n',
    ],
    [
      'request to a fixed URL',
      'import requests\ndef f():\n    return requests.get("https://api.example.com/v1/status").json()\n',
    ],
    [
      'ast.literal_eval',
      'import ast\nfrom flask import request\ndef f():\n    return ast.literal_eval(request.args.get("expr"))\n',
    ],
  ];
  for (const [name, src] of safe) {
    it(`${name} is silent`, () => {
      expect(scan(src)).toHaveLength(0);
    });
  }

  it('a comment demonstrating the vulnerable call is not the call', () => {
    expect(
      scan(
        'from flask import request\ndef f():\n    # never do os.system("ping " + request.args.get("h"))\n    return "ok"\n'
      )
    ).toHaveLength(0);
  });

  it('non-Python files are ignored', () => {
    expect(scan('os.system("ping " + request.args.get("h"))', 'src/app.js')).toHaveLength(0);
  });
});

describe('probePythonSecurity — path assembly without a string operator', () => {
  // Found by a hand-written positive control during the fix-PR corpus work.
  // The harvested pairs proved nothing; the control caught a live gap. That is
  // the argument for writing controls even when you think you have real data.
  //
  // os.path.join and pathlib are how Python actually builds paths, more common
  // than concatenation, and the interpolation gate saw neither: no f-string,
  // no %, no .format, no +.
  const shapes = [
    [
      'os.path.join with a request value',
      'import os\nfrom flask import request, send_file\nBASE = "/srv/files"\ndef d():\n    return send_file(os.path.join(BASE, request.args.get("name")))\n',
    ],
    [
      'os.path.join one hop through a variable',
      'import os\nfrom flask import request, send_file\nBASE = "/srv/files"\ndef d():\n    name = request.args.get("name")\n    return send_file(os.path.join(BASE, name))\n',
    ],
    [
      'open(os.path.join(...))',
      'import os\nfrom flask import request\ndef d():\n    with open(os.path.join("docs", request.args.get("n"))) as fh:\n        return fh.read()\n',
    ],
    [
      'pathlib division operator',
      'from pathlib import Path\nfrom flask import request\ndef d():\n    return (Path("uploads") / request.args.get("n")).read_text()\n',
    ],
  ];
  for (const [name, src] of shapes) {
    it(`${name} fires CWE-22`, () => {
      expect(scan(src).some((x) => x.cwe === 'CWE-22')).toBe(true);
    });
  }

  it('a resolved path with a containment check stays silent', () => {
    // This is the fix the remediation recommends. Flagging it would be advising
    // a change and then reporting the change.
    const src =
      'from pathlib import Path\nfrom flask import request\nBASE = Path("uploads").resolve()\ndef d():\n    t = (BASE / request.args.get("n")).resolve()\n    if not t.is_relative_to(BASE):\n        return "no", 400\n    return t.read_text()\n';
    expect(scan(src).filter((x) => x.cwe === 'CWE-22')).toHaveLength(0);
  });

  it('joining constants is not a finding', () => {
    expect(scan('import os\ndef d():\n    return os.path.join("a", "b", "c.txt")\n')).toHaveLength(
      0
    );
  });
});
