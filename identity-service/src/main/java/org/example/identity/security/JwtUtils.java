package org.example.identity.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.example.identity.entity.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Component
public class JwtUtils {

    private final SecretKey signingKey;
    private final long accessTokenExpiration;

    public JwtUtils(@Value("${app.jwt.secret}") String secret,
                    @Value("${app.jwt.access-token-expiration}") long accessTokenExpiration) {
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpiration = accessTokenExpiration;
    }

    public String generateAccessToken(User user) {
        Date now = new Date();
        return Jwts.builder()
                .setId(UUID.randomUUID().toString())                       // jti (Bài 4)
                .setSubject(user.getUsername())                            // sub
                .claim("userId", user.getId())
                .claim("roles", List.of(user.getRole().name()))            // Bài 1-2 (RBAC)
                .claim("permissions", user.getRole().getPermissions())     // Bài 6 (PBAC)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + accessTokenExpiration))
                // Cố định HS256 để Product-Service (Nimbus JwtDecoder) verify được
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Verify chữ ký + hạn dùng, trả về Claims. Ném JwtException nếu token không hợp lệ.
     */
    public Claims parseClaims(String token) throws JwtException {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public long getAccessTokenExpiration() {
        return accessTokenExpiration;
    }
}
