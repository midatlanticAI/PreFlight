// XL-013 / KT-AUTH-001 negative fixture.
// Signature verified with the key before the claims are trusted.
fun subject(token: String, key: SecretKey): String {
    val claims = Jwts.parser().verifyWith(key).build().parseSignedClaims(token)
    return claims.payload.subject
}
