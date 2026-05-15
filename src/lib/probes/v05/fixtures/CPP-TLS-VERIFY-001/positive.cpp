// XL-004 / CPP-TLS-VERIFY-001 positive fixture.
// Asio TLS context with peer verification turned off.
void setup(boost::asio::ssl::context &ctx) {
    ctx.set_verify_mode(boost::asio::ssl::verify_none);
}
