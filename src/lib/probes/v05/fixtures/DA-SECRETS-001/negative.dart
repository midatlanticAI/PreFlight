// XL-006 / DA-SECRETS-001 negative fixture.
// Key injected at build time via --dart-define, not a literal.
class Config {
  static const apiKey = String.fromEnvironment('OPENAI_API_KEY');
}
