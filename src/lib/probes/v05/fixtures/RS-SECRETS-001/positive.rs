// XL-006 / RS-SECRETS-001 positive fixture.
// Credential-named binding assigned a literal (synthetic, low-entropy).
pub fn client() -> Client {
    let api_key = "AAAAAAAAAAAAAAAAAAAAAAAA";
    Client::new(api_key)
}
