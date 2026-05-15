// XL-006 / SC-SECRETS-001 negative fixture.
// Key read from the environment, not bound to a literal.
object Config {
  private val apiKey: String = sys.env("OPENAI_API_KEY")
  def key: String = apiKey
}
