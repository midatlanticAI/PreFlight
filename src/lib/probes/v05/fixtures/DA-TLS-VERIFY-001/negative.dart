// XL-004 / DA-TLS-VERIFY-001 negative fixture.
// Pinned-certificate comparison instead of unconditional trust.
HttpClient makeClient(String pinnedSha1) {
  final client = HttpClient();
  client.badCertificateCallback = (cert, host, port) => cert.sha1 == pinnedSha1;
  return client;
}
