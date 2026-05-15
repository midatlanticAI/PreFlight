// XL-004 / SC-TLS-VERIFY-001 negative fixture.
// Delegates to the platform default trust manager (real validation).
class DelegatingTrust(default: javax.net.ssl.X509TrustManager)
    extends javax.net.ssl.X509TrustManager {
  def checkServerTrusted(chain: Array[X509Certificate], authType: String): Unit =
    default.checkServerTrusted(chain, authType)
  def getAcceptedIssuers(): Array[X509Certificate] = default.getAcceptedIssuers()
}
