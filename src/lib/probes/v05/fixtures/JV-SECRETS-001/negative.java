// XL-006 / JV-SECRETS-001 negative fixture.
// The key is read from the environment, not bound to a literal.
public class ApiClient {
    private final String apiKey = System.getenv("OPENAI_API_KEY");
    String key() { return apiKey; }
}
