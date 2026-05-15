// XL-006 / SW-SECRETS-001 negative fixture.
// Key read from the environment, not bound to a literal.
struct Config {
    static let apiKey = ProcessInfo.processInfo.environment["OPENAI_API_KEY"]
}
