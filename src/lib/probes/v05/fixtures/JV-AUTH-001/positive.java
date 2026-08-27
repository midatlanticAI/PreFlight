package com.example.auth;

import io.jsonwebtoken.Jwts;

public class TokenService {
    public String subject(String token) {
        return Jwts.parser().build().parseClaimsJwt(token).getBody().getSubject();
    }

    public String mint(String subject) {
        return Jwts.builder().subject(subject).signWith(Jwts.SIG.NONE).compact();
    }
}
