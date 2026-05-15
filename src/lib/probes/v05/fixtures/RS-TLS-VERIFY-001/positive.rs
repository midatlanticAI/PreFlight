// XL-004 / RS-TLS-VERIFY-001 positive fixture.
// Certificate verification turned off for the whole client.
pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}
