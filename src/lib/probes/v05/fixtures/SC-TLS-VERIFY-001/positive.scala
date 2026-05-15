// XL-004 / SC-TLS-VERIFY-001 positive fixture.
// X509TrustManager whose server-trust check is an empty body.
class TrustAll extends javax.net.ssl.X509TrustManager {
  def checkClientTrusted(chain: Array[X509Certificate], authType: String): Unit = {}
  def checkServerTrusted(chain: Array[X509Certificate], authType: String): Unit = {}
  def getAcceptedIssuers(): Array[X509Certificate] = Array.empty
}
