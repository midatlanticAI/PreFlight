/* XL-004 / CC-TLS-VERIFY-001 positive fixture.
   OpenSSL peer verification turned off. */
void configure(SSL_CTX *ctx) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
}
