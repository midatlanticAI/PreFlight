// XL-013 / KT-AUTH-001 positive fixture.
// parseClaimsJwt parses an UNSIGNED token: the signature is never checked.
fun subject(token: String): String {
    val claims = Jwts.parser().build().parseClaimsJwt(token)
    return claims.body.subject
}
