// XL-004 / CS-TLS-VERIFY-001 positive fixture.
// Certificate validation callback that always returns true.
public class Http {
    public HttpClient Make() {
        var handler = new HttpClientHandler();
        handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true;
        return new HttpClient(handler);
    }
}
