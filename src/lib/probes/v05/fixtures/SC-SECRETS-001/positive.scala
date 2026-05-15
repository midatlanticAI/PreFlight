// XL-006 / SC-SECRETS-001 positive fixture.
// Credential-named val assigned a literal (synthetic, low-entropy).
object Config {
  private val apiKey: String = "AAAAAAAAAAAAAAAAAAAAAAAA"
  def key: String = apiKey
}
