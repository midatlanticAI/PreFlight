// XL-013 / CPP-AUTH-001 positive fixture.
#include <jwt/jwt.hpp>

std::string subject(const std::string& token) {
    auto dec = jwt::decode(token, jwt::params::algorithms({"none", "HS256"}));
    return dec.payload().get_claim_value<std::string>("sub");
}
