// XL-006 / CPP-SECRETS-001 negative fixture.
// Key read from the environment, not bound to a literal.
std::string clientKey() {
    const char *apiKey = std::getenv("OPENAI_API_KEY");
    return apiKey ? apiKey : "";
}
