package com.example.productservice.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;

/** Resource Server chỉ VERIFY token, không bao giờ tự phát hành token. */
@Component
public class JwtUtils {

    private final Key signingKey;

    public JwtUtils(@Value("${app.jwt.secret}") String secret) {
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Kiểm tra chữ ký + hạn dùng (exp) và trả về Claims.
     * Ném JwtException (SignatureException, ExpiredJwtException, MalformedJwtException...) nếu không hợp lệ.
     */
    public Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
