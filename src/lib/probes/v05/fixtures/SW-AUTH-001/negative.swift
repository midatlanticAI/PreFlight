import SwiftJWT

struct TokenService {
    func mint(claims: MyClaims, key: Data) throws -> String {
        var jwt = JWT(claims: claims)
        return try jwt.sign(using: .hs256(key: key))
    }
}
