package org.example.product.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.util.List;

/**
 * Bài 2: "Trạm kiểm soát" - giải mã JWT do Identity-Service ký, nạp Authentication vào SecurityContext.
 * Product-Service không có DB User, hoàn toàn tin vào chữ ký của token.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final SecretKey signingKey;

    public JwtAuthenticationFilter(SecretKey signingKey) {
        this.signingKey = signingKey;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // 1. Lấy JWT từ header "Authorization: Bearer <token>"
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            try {
                // 2. Verify chữ ký bằng Secret Key dùng chung
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(signingKey)
                        .build()
                        .parseClaimsJws(token)
                        .getBody();

                // 3. Trích xuất username + roles (+ permissions cho Bài 6)
                String username = claims.getSubject();
                List<?> roles = claims.get("roles", List.class);
                List<?> permissions = claims.get("permissions", List.class);

                // 4-5. Roles -> SimpleGrantedAuthority, nạp vào SecurityContextHolder
                var authentication = new UsernamePasswordAuthenticationToken(
                        username, null, JwtAuthoritiesMapper.toAuthorities(roles, permissions));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (JwtException | IllegalArgumentException ex) {
                // Token sai/hết hạn -> không set Authentication, Spring Security sẽ trả 401
                SecurityContextHolder.clearContext();
            }
        }

        filterChain.doFilter(request, response);
    }
}
