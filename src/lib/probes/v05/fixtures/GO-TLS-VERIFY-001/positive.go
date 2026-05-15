// XL-004 / GO-TLS-VERIFY-001 positive fixture.
// Certificate verification disabled on the TLS client config.
package httpx

func Client() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr}
}
