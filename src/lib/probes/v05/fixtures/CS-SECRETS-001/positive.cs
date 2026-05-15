// XL-006 / CS-SECRETS-001 positive fixture.
// Credential-named constant assigned a literal (synthetic, low-entropy).
public class ApiClient {
    private const string ApiKey = "AAAAAAAAAAAAAAAAAAAAAAAA";
    public string Key() => ApiKey;
}
