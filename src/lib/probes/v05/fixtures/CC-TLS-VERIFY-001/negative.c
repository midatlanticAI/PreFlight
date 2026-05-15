/* XL-004 / CC-TLS-VERIFY-001 negative fixture.
   Peer verification on; CA bundle loaded. */
void configure(SSL_CTX *ctx) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_load_verify_locations(ctx, "/etc/ssl/certs/ca.pem", NULL);
}
