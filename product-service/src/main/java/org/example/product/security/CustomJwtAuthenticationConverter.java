package org.example.product.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;

/**
 * Bài 6: Spring Security không biết claim "permissions" -> tự map sang GrantedAuthority.
 */
public class CustomJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        // 1. Lấy List<String> từ claim "permissions" (giữ thêm "roles" để hasRole('ADMIN') vẫn chạy)
        List<String> permissions = jwt.getClaimAsStringList("permissions");
        List<String> roles = jwt.getClaimAsStringList("roles");

        // 2-3. Map sang SimpleGrantedAuthority và trả về UsernamePasswordAuthenticationToken
        return new UsernamePasswordAuthenticationToken(
                jwt.getSubject(), jwt, JwtAuthoritiesMapper.toAuthorities(roles, permissions));
    }
}
