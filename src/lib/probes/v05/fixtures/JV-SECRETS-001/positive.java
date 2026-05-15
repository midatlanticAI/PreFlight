// XL-006 / JV-SECRETS-001 positive fixture.
// Credential-named constant assigned a literal (synthetic, low-entropy).
public class ApiClient {
    private static final String API_KEY = "AAAAAAAAAAAAAAAAAAAAAAAA";
    String key() { return API_KEY; }
}
