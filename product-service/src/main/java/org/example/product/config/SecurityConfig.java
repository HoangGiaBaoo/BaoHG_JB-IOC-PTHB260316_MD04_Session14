package org.example.product.config;

import io.jsonwebtoken.security.Keys;
import org.example.product.security.CustomJwtAuthenticationConverter;
import org.example.product.security.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity // kích hoạt @PreAuthorize
public class SecurityConfig {

    private final SecretKey signingKey;
    private final String mode;

    public SecurityConfig(@Value("${app.jwt.secret}") String secret,
                          @Value("${app.security.mode:filter}") String mode) {
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.mode = mode;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/error").permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(authenticationEntryPoint())
                        .accessDeniedHandler(accessDeniedHandler()));

        if ("resource-server".equals(mode)) {
            // Bài 6: Resource Server chuẩn + Converter tự viết cho claim "permissions"
            http.oauth2ResourceServer(oauth2 -> oauth2
                    .authenticationEntryPoint(authenticationEntryPoint())
                    .accessDeniedHandler(accessDeniedHandler())
                    .jwt(jwt -> jwt
                            .decoder(jwtDecoder())
                            .jwtAuthenticationConverter(new CustomJwtAuthenticationConverter())));
        } else {
            // Bài 2: Filter tự viết, đặt trước UsernamePasswordAuthenticationFilter
            http.addFilterBefore(new JwtAuthenticationFilter(signingKey), UsernamePasswordAuthenticationFilter.class);
        }
        return http.build();
    }

    private JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withSecretKey(signingKey).macAlgorithm(MacAlgorithm.HS256).build();
    }

    private AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, ex) -> writeJson(response, 401, "Unauthorized");
    }

    private AccessDeniedHandler accessDeniedHandler() {
        return (request, response, ex) -> writeJson(response, 403, "Forbidden - ban khong co quyen");
    }

    private static void writeJson(jakarta.servlet.http.HttpServletResponse response, int status, String message)
            throws java.io.IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"status\":" + status + ",\"message\":\"" + message + "\"}");
    }
}
