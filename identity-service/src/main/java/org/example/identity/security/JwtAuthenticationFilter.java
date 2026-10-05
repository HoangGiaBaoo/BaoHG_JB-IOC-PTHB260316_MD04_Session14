package org.example.identity.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.identity.service.TokenBlacklistService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Xác thực Access Token cho các API cần đăng nhập của Identity-Service (vd: /api/auth/logout).
 * Token đã nằm trong blacklist (đã logout) sẽ bị chặn với 401.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;
    private final TokenBlacklistService blacklistService;

    public JwtAuthenticationFilter(JwtUtils jwtUtils, TokenBlacklistService blacklistService) {
        this.jwtUtils = jwtUtils;
        this.blacklistService = blacklistService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.substring(7);
        try {
            Claims claims = jwtUtils.parseClaims(token);
            if (blacklistService.isBlacklisted(claims.getId())) {
                writeUnauthorized(response, "Token da bi thu hoi (logout)");
                return;
            }

            List<?> roles = claims.get("roles", List.class);
            List<SimpleGrantedAuthority> authorities = roles == null ? List.of() : roles.stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                    .toList();
            var authentication = new UsernamePasswordAuthenticationToken(claims.getSubject(), token, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (JwtException | IllegalArgumentException ex) {
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    private void writeUnauthorized(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"status\":401,\"message\":\"" + message + "\"}");
    }
}
