// XL-006 / KT-SECRETS-001 negative fixture.
// Key read from the environment, not bound to a literal.
object Config {
    private val apiKey = System.getenv("OPENAI_API_KEY")
    fun key() = apiKey
}
