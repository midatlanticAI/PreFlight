import SwiftJWT

struct TokenService {
    func mint(claims: MyClaims) throws -> String {
        var jwt = JWT(claims: claims)
        return try jwt.sign(using: .none)
    }
}
