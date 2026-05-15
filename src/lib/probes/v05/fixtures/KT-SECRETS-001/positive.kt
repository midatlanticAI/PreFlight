// XL-006 / KT-SECRETS-001 positive fixture.
// Credential-named constant assigned a literal (synthetic, low-entropy).
object Config {
    private const val API_KEY = "AAAAAAAAAAAAAAAAAAAAAAAA"
    fun key() = API_KEY
}
