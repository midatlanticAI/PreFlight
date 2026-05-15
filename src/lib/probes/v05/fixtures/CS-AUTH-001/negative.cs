// XL-013 / CS-AUTH-001 negative fixture.
// All validation flags on; signing key supplied.
public class Auth {
    public TokenValidationParameters Params(SecurityKey key) {
        return new TokenValidationParameters {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key
        };
    }
}
