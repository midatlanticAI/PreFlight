// XL-004 / JV-TLS-VERIFY-001 negative fixture.
// Delegates to the platform default trust manager (real validation).
public class DelegatingTrust implements javax.net.ssl.X509TrustManager {
    private final X509TrustManager def;
    public void checkServerTrusted(X509Certificate[] c, String a) throws CertificateException { def.checkServerTrusted(c, a); }
    public X509Certificate[] getAcceptedIssuers() { return def.getAcceptedIssuers(); }
}
