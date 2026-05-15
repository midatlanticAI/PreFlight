// XL-004 / DA-TLS-VERIFY-001 positive fixture.
// badCertificateCallback accepts any certificate.
HttpClient makeClient() {
  final client = HttpClient();
  client.badCertificateCallback = (cert, host, port) => true;
  return client;
}
