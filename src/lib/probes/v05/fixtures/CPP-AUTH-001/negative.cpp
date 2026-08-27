// XL-013 / CPP-AUTH-001 negative fixture.
#include <jwt/jwt.hpp>

std::string subject(const std::string& token, const std::string& secret) {
    auto dec = jwt::decode(token, jwt::params::algorithms({"HS256"}), jwt::params::secret(secret));
    return dec.payload().get_claim_value<std::string>("sub");
}
