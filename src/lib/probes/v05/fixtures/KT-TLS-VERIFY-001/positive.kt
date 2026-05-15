// XL-004 / KT-TLS-VERIFY-001 positive fixture.
// X509TrustManager whose server-trust check is an empty body.
class TrustAll : X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
}
