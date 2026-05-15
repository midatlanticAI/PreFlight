// XL-004 / KT-TLS-VERIFY-001 negative fixture.
// Delegates to the platform default trust manager (real validation).
class DelegatingTrust(private val def: X509TrustManager) : X509TrustManager {
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) { def.checkServerTrusted(chain, authType) }
    override fun getAcceptedIssuers(): Array<X509Certificate> = def.acceptedIssuers
}
