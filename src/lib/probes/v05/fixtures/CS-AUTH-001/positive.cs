// XL-013 / CS-AUTH-001 positive fixture.
// JWT validation flags turned off: forged tokens pass.
public class Auth {
    public TokenValidationParameters Params() {
        return new TokenValidationParameters {
            ValidateIssuer = false,
            ValidateAudience = false
        };
    }
}
