// XL-004 / CS-TLS-VERIFY-001 negative fixture.
// Callback that actually inspects the policy errors.
public class Http {
    public HttpClient Make() {
        var handler = new HttpClientHandler();
        handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => e == SslPolicyErrors.None;
        return new HttpClient(handler);
    }
}
