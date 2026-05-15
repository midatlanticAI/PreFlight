# XL-004 / RB-TLS-VERIFY-001 negative fixture.
# Default peer verification with an explicit CA file.
def client(http)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER
  http.ca_file = "/etc/ssl/certs/ca.pem"
  http
end
