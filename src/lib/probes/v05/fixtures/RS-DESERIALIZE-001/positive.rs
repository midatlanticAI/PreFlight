// XL-001 / RS-DESERIALIZE-001 positive fixture.
// from_str on an untrusted request body with no prior size bound.
pub fn handle(body: String) -> User {
    let user: User = serde_json::from_str(&body).unwrap();
    user
}
