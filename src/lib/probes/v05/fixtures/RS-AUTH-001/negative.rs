use hmac::Hmac;
use jwt::VerifyWithKey;
use sha2::Sha256;

pub fn subject(raw: &str, key: &Hmac<Sha256>) -> String {
    let claims: Claims = raw.verify_with_key(key).unwrap();
    claims.sub
}
