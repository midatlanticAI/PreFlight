// XL-006 / GO-SECRETS-001 negative fixture.
// The key is read from the environment, not bound to a literal.
package client

func New() *Client {
	apiKey := os.Getenv("OPENAI_API_KEY")
	return &Client{key: apiKey}
}
