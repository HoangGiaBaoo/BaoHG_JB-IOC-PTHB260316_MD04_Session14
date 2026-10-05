package org.example.identity.controller;

import jakarta.validation.Valid;
import org.example.identity.dto.LoginRequest;
import org.example.identity.dto.MessageResponse;
import org.example.identity.dto.RefreshTokenRequest;
import org.example.identity.dto.TokenResponseDTO;
import org.example.identity.service.AuthService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponseDTO> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponseDTO> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refreshToken(request.refreshToken()));
    }

    // Yêu cầu Access Token hợp lệ (đã được JwtAuthenticationFilter kiểm tra).
    // Body { "refreshToken": "..." } là tùy chọn.
    @PostMapping("/logout")
    public ResponseEntity<MessageResponse> logout(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
                                                  @RequestBody(required = false) RefreshTokenRequest request) {
        String accessToken = authorization.substring("Bearer ".length());
        authService.logout(accessToken, request != null ? request.refreshToken() : null);
        return ResponseEntity.ok(new MessageResponse(200, "Dang xuat thanh cong"));
    }
}
