// XL-004 / JV-TLS-VERIFY-001 positive fixture.
// X509TrustManager whose server-trust check is an empty body.
public class TrustAll implements javax.net.ssl.X509TrustManager {
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
}
