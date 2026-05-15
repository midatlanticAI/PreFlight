// v1 hardening — adversarial / false-positive suite for the five core
// families across representative languages.
//
// Two failure modes a security scanner must resist:
//   1. False NEGATIVE on an obfuscated-but-real positive (attacker hides
//      the pattern; the probe must still fire).
//   2. False POSITIVE on a safe-lookalike (the secure API resembles the
//      unsafe one; the probe must stay silent or it becomes noise users
//      learn to ignore).
//
// Fixtures already cover the canonical pos/neg. This suite covers the
// tricky middle: safe APIs that look dangerous, and dangerous code that
// looks safe.

import { describe, it, expect } from 'vitest';
import { PROBE_MANIFEST_V05 } from '../lib/probes/v05/manifest.js';
import { runShadow } from '../lib/probes/v05/shadow.js';

const A = (id) => PROBE_MANIFEST_V05[id];
// Neutral path that passes every language scope filter (not test/, not
// src/lib/probes, not the v05 fixture tree).
const f = (path, content) => [{ path: `adv/${path}`, content }];
const fires = (id, path, src) => runShadow(A(id), f(path, src)).length;

describe('adversarial XL-001 (deserialization): safe APIs stay silent', () => {
  it('PY safe loaders + literal do not fire', () => {
    expect(fires('PY-DESERIALIZE-001', 'a.py', 'data = yaml.safe_load(body)')).toBe(0);
    expect(fires('PY-DESERIALIZE-001', 'a.py', 'cfg = json.loads(req.body)')).toBe(0);
  });
  it('RB Marshal stays critical but YAML.safe_load is silent', () => {
    expect(fires('RB-DESERIALIZE-001', 'a.rb', 'x = YAML.safe_load(input)')).toBe(0);
    expect(fires('RB-DESERIALIZE-001', 'a.rb', 'x = Marshal.load(input)')).toBeGreaterThan(0);
  });
  it('PHP unserialize with allowed_classes:false is silent; bare is not', () => {
    expect(
      fires(
        'PHP-DESERIALIZE-001',
        'a.php',
        "<?php $x = unserialize($d, ['allowed_classes' => false]);"
      )
    ).toBe(0);
    expect(
      fires('PHP-DESERIALIZE-001', 'a.php', '<?php $x = unserialize($_GET["d"]);')
    ).toBeGreaterThan(0);
  });
  it('EX binary_to_term [:safe] is silent; bare fires', () => {
    expect(fires('EX-DESERIALIZE-001', 'a.ex', 'x = :erlang.binary_to_term(p, [:safe])')).toBe(0);
    expect(fires('EX-DESERIALIZE-001', 'a.ex', 'x = :erlang.binary_to_term(p)')).toBeGreaterThan(0);
  });
});

describe('adversarial XL-002 (raw SQL): parameterized stays silent', () => {
  it('PY parameterized execute is silent; f-string fires', () => {
    expect(
      fires('PY-SQL-RAW-001', 'a.py', 'cursor.execute("SELECT * FROM t WHERE id = %s", [uid])')
    ).toBe(0);
    expect(
      fires('PY-SQL-RAW-001', 'a.py', 'cursor.execute(f"SELECT * FROM t WHERE id = {uid}")')
    ).toBeGreaterThan(0);
  });
  it('SC Slick ${} bind is silent; #${} literal splice fires', () => {
    expect(fires('SC-SQL-RAW-001', 'a.scala', 'sql"SELECT x WHERE n = ${name}".as[String]')).toBe(
      0
    );
    expect(
      fires('SC-SQL-RAW-001', 'a.scala', 'sql"SELECT x WHERE n = #${name}".as[String]')
    ).toBeGreaterThan(0);
  });
  it('RB hash/bind form is silent; interpolation fires', () => {
    expect(fires('RB-SQL-RAW-001', 'a.rb', 'User.where(name: params[:name])')).toBe(0);
    expect(fires('RB-SQL-RAW-001', 'a.rb', 'User.where("name = ?", params[:name])')).toBe(0);
    expect(
      fires('RB-SQL-RAW-001', 'a.rb', 'User.where("name = \'#{params[:name]}\'")')
    ).toBeGreaterThan(0);
  });
  it('GO Sprintf fires; placeholder is silent', () => {
    expect(fires('GO-SQL-RAW-001', 'a.go', 'db.Query("SELECT * FROM t WHERE id = $1", id)')).toBe(
      0
    );
    expect(
      fires('GO-SQL-RAW-001', 'a.go', 'db.Query(fmt.Sprintf("SELECT * FROM t WHERE id = %s", id))')
    ).toBeGreaterThan(0);
  });
});

describe('adversarial XL-004 (TLS): the secure setting stays silent', () => {
  it('PY verify=True / default is silent; verify=False fires', () => {
    expect(fires('PY-TLS-VERIFY-001', 'a.py', 'requests.get(u, verify=True)')).toBe(0);
    expect(fires('PY-TLS-VERIFY-001', 'a.py', 'requests.get(u, verify=False)')).toBeGreaterThan(0);
  });
  it('GO InsecureSkipVerify:false is silent; true fires', () => {
    expect(fires('GO-TLS-VERIFY-001', 'a.go', 'tls.Config{InsecureSkipVerify: false}')).toBe(0);
    expect(
      fires('GO-TLS-VERIFY-001', 'a.go', 'tls.Config{InsecureSkipVerify: true}')
    ).toBeGreaterThan(0);
  });
  it('RS danger_accept_invalid_certs(false) is silent; (true) fires', () => {
    expect(fires('RS-TLS-VERIFY-001', 'a.rs', '.danger_accept_invalid_certs(false)')).toBe(0);
    expect(
      fires('RS-TLS-VERIFY-001', 'a.rs', '.danger_accept_invalid_certs(true)')
    ).toBeGreaterThan(0);
  });
  it('RB VERIFY_PEER is silent; VERIFY_NONE fires', () => {
    expect(fires('RB-TLS-VERIFY-001', 'a.rb', 'http.verify_mode = OpenSSL::SSL::VERIFY_PEER')).toBe(
      0
    );
    expect(
      fires('RB-TLS-VERIFY-001', 'a.rb', 'http.verify_mode = OpenSSL::SSL::VERIFY_NONE')
    ).toBeGreaterThan(0);
  });
});

describe('adversarial XL-006 (secrets): env + placeholders stay silent', () => {
  it('PY env-loaded + placeholder is silent; literal fires', () => {
    expect(fires('PY-SECRETS-001', 'a.py', 'api_key = os.environ["OPENAI_API_KEY"]')).toBe(0);
    expect(fires('PY-SECRETS-001', 'a.py', 'api_key = "your_key_here_placeholder_value"')).toBe(0);
  });
  it('GO os.Getenv is silent; literal assignment fires', () => {
    expect(fires('GO-SECRETS-001', 'a.go', 'apiKey := os.Getenv("OPENAI_API_KEY")')).toBe(0);
    expect(
      fires('GO-SECRETS-001', 'a.go', 'apiKey := "abcdefghijklmnopqrstuvwxyz0"')
    ).toBeGreaterThan(0);
  });
  it('JV @Value / System.getenv is silent; literal fires', () => {
    expect(
      fires('JV-SECRETS-001', 'a.java', 'private final String apiKey = System.getenv("K");')
    ).toBe(0);
    expect(
      fires('JV-SECRETS-001', 'a.java', 'static final String API_KEY = "abcdefghijklmnopqrstuvwx";')
    ).toBeGreaterThan(0);
  });
  it('RB ENV.fetch is silent; constant literal fires', () => {
    expect(fires('RB-SECRETS-001', 'a.rb', 'API_KEY = ENV.fetch("OPENAI_API_KEY")')).toBe(0);
    expect(
      fires('RB-SECRETS-001', 'a.rb', 'API_KEY = "abcdefghijklmnopqrstuvwxyz0"')
    ).toBeGreaterThan(0);
  });
});

describe('adversarial XL-013 (token verification): verified path stays silent', () => {
  it('CS Validate*=true is silent; =false fires', () => {
    expect(
      fires('CS-AUTH-001', 'a.cs', 'new TokenValidationParameters { ValidateIssuer = true }')
    ).toBe(0);
    expect(
      fires('CS-AUTH-001', 'a.cs', 'new TokenValidationParameters { ValidateIssuer = false }')
    ).toBeGreaterThan(0);
  });
  it('KT parseSignedClaims is silent; parseClaimsJwt fires', () => {
    expect(
      fires(
        'KT-AUTH-001',
        'a.kt',
        'val c = Jwts.parser().verifyWith(k).build().parseSignedClaims(t)'
      )
    ).toBe(0);
    expect(
      fires('KT-AUTH-001', 'a.kt', 'val c = Jwts.parser().build().parseClaimsJwt(t)')
    ).toBeGreaterThan(0);
  });
});

describe('adversarial: obfuscated positives still fire', () => {
  it('PY pickle.load with padded args still fires', () => {
    expect(
      fires('PY-DESERIALIZE-001', 'a.py', 'obj = pickle.load(  request.data  )')
    ).toBeGreaterThan(0);
  });
  it('GO InsecureSkipVerify with odd spacing still fires', () => {
    expect(fires('GO-TLS-VERIFY-001', 'a.go', '  InsecureSkipVerify:    true,')).toBeGreaterThan(0);
  });
  it('RB Marshal.load via Marshal.restore alias still fires', () => {
    expect(fires('RB-DESERIALIZE-001', 'a.rb', 'x = Marshal.restore(blob)')).toBeGreaterThan(0);
  });
});
