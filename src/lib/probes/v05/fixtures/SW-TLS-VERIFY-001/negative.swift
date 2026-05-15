// XL-004 / SW-TLS-VERIFY-001 negative fixture.
// Evaluate the server trust, then fall back to default handling.
func urlSession(_ s: URLSession, didReceive c: URLAuthenticationChallenge,
                completionHandler ch: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    var error: CFError?
    if let t = c.protectionSpace.serverTrust, SecTrustEvaluateWithError(t, &error) {
        ch(.performDefaultHandling, nil)
    } else {
        ch(.cancelAuthenticationChallenge, nil)
    }
}
