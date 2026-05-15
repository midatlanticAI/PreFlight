// XL-006 / GO-SECRETS-001 positive fixture.
// Credential-named binding assigned a literal (synthetic, low-entropy).
package client

func New() *Client {
	apiKey := "AAAAAAAAAAAAAAAAAAAAAAAA"
	return &Client{key: apiKey}
}
