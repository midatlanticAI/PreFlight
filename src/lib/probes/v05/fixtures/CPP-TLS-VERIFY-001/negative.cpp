// XL-004 / CPP-TLS-VERIFY-001 negative fixture.
// Peer verification on; default trust paths loaded.
void setup(boost::asio::ssl::context &ctx) {
    ctx.set_default_verify_paths();
    ctx.set_verify_mode(boost::asio::ssl::verify_peer);
}
