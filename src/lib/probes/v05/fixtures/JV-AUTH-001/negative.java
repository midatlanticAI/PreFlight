package com.example.auth;

import io.jsonwebtoken.Jwts;
import javax.crypto.SecretKey;

public class TokenService {
    public String subject(String token, SecretKey key) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload().getSubject();
    }

    public String mint(String subject, SecretKey key) {
        return Jwts.builder().subject(subject).signWith(key).compact();
    }
}
