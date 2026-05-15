# XL-004 / RB-TLS-VERIFY-001 positive fixture.
# Net::HTTP with certificate verification turned off.
def client(http)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  http
end
