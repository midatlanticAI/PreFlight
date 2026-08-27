package auth

import "github.com/golang-jwt/jwt/v5"

func Mint(claims jwt.Claims, secret []byte) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(secret)
}

func Parse(raw string, keyFunc jwt.Keyfunc) (*jwt.Token, error) {
	return jwt.Parse(raw, keyFunc, jwt.WithValidMethods([]string{"HS256"}))
}
