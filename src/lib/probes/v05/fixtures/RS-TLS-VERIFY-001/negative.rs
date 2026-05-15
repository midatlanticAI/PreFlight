// XL-004 / RS-TLS-VERIFY-001 negative fixture.
// Default verification; a private CA is added explicitly instead.
pub fn client(ca: reqwest::Certificate) -> reqwest::Client {
    reqwest::Client::builder()
        .add_root_certificate(ca)
        .build()
        .unwrap()
}
