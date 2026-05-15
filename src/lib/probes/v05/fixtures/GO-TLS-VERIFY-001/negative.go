// XL-004 / GO-TLS-VERIFY-001 negative fixture.
// Default verification; a private CA pool is supplied instead.
package httpx

func Client(pool *x509.CertPool) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}
	return &http.Client{Transport: tr}
}
