package org.example.product.security;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Map claim "roles" -> ROLE_xxx (RBAC, Bài 2) và claim "permissions" -> xxx (PBAC, Bài 6).
 * Dùng chung cho cả JwtAuthenticationFilter và CustomJwtAuthenticationConverter.
 */
public final class JwtAuthoritiesMapper {

    private JwtAuthoritiesMapper() {
    }

    public static List<SimpleGrantedAuthority> toAuthorities(Collection<?> roles, Collection<?> permissions) {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        if (roles != null) {
            roles.forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
        }
        if (permissions != null) {
            permissions.forEach(permission -> authorities.add(new SimpleGrantedAuthority(permission.toString())));
        }
        return authorities;
    }
}
