// XL-006 / RS-SECRETS-001 negative fixture.
// The key is read from the environment, not bound to a literal.
pub fn client() -> Client {
    let api_key = std::env::var("OPENAI_API_KEY").expect("OPENAI_API_KEY");
    Client::new(&api_key)
}
