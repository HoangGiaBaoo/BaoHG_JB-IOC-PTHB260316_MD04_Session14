package org.example.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

/**
 * Bài 5: Chặn token đã logout (nằm trong blacklist Redis) ngay tại Gateway,
 * request không được forward vào service phía sau.
 */
@Component
public class TokenBlacklistGlobalFilter implements GlobalFilter, Ordered {

    private static final String BLACKLIST_PREFIX = "blacklist:";

    private final ReactiveStringRedisTemplate redisTemplate;
    private final SecretKey signingKey;

    public TokenBlacklistGlobalFilter(ReactiveStringRedisTemplate redisTemplate,
                                      @Value("${app.jwt.secret}") String secret) {
        this.redisTemplate = redisTemplate;
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 1. Trích xuất token từ header Authorization
        String header = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith("Bearer ")) {
            return chain.filter(exchange); // vd: /api/auth/login -> cho qua
        }

        // 2. Parse JWT để lấy jti
        String jti;
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(header.substring(7))
                    .getBody();
            jti = claims.getId();
        } catch (JwtException | IllegalArgumentException ex) {
            return unauthorized(exchange.getResponse(), "Token khong hop le hoac da het han");
        }
        if (jti == null) {
            return chain.filter(exchange);
        }

        // 3-5. Hỏi Redis (non-blocking): có trong blacklist -> 401, không -> đi tiếp
        return redisTemplate.hasKey(BLACKLIST_PREFIX + jti)
                .flatMap(isBlacklisted -> Boolean.TRUE.equals(isBlacklisted)
                        ? unauthorized(exchange.getResponse(), "Token da bi thu hoi (logout)")
                        : chain.filter(exchange));
    }

    private Mono<Void> unauthorized(ServerHttpResponse response, String message) {
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        byte[] body = ("{\"status\":401,\"message\":\"" + message + "\"}").getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = response.bufferFactory().wrap(body);
        return response.writeWith(Mono.just(buffer));
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE; // chạy trước mọi filter khác
    }
}
