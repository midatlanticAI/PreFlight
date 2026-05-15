// XL-004 / SW-TLS-VERIFY-001 positive fixture.
// Auth-challenge delegate that trusts the server without evaluation.
func urlSession(_ s: URLSession, didReceive c: URLAuthenticationChallenge,
                completionHandler ch: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    ch(.useCredential, URLCredential(trust: c.protectionSpace.serverTrust!))
}
