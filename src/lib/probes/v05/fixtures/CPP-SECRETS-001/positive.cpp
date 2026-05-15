// XL-006 / CPP-SECRETS-001 positive fixture.
// Credential-named std::string assigned a literal (synthetic, low-entropy).
std::string clientKey() {
    const std::string apiKey = "AAAAAAAAAAAAAAAAAAAAAAAA";
    return apiKey;
}
