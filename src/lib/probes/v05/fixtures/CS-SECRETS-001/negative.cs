// XL-006 / CS-SECRETS-001 negative fixture.
// Key read from the environment, not bound to a literal.
public class ApiClient {
    private readonly string apiKey = Environment.GetEnvironmentVariable("OPENAI_API_KEY");
    public string Key() => apiKey;
}
