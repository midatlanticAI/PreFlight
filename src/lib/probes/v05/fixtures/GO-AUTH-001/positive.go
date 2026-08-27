package auth

import "github.com/golang-jwt/jwt/v5"

func Mint(claims jwt.Claims) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	return tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
}

func Parse(raw string, keyFunc jwt.Keyfunc) (*jwt.Token, error) {
	return jwt.NewParser(jwt.WithoutClaimsValidation()).Parse(raw, keyFunc)
}
