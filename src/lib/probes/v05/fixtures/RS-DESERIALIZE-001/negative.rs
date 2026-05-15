// XL-001 / RS-DESERIALIZE-001 negative fixture.
// Deserializing a constant literal, not an untrusted body.
pub fn defaults() -> Cfg {
    let cfg: Cfg = serde_json::from_str(r#"{"retries":3}"#).unwrap();
    cfg
}
