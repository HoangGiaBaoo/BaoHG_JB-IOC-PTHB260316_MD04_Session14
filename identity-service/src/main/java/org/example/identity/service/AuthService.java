package org.example.identity.service;

import io.jsonwebtoken.Claims;
import org.example.identity.dto.LoginRequest;
import org.example.identity.dto.TokenResponseDTO;
import org.example.identity.entity.RefreshToken;
import org.example.identity.entity.User;
import org.example.identity.exception.TokenRefreshException;
import org.example.identity.repository.UserRepository;
import org.example.identity.security.JwtUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistService blacklistService;

    public AuthService(AuthenticationManager authenticationManager, UserRepository userRepository, JwtUtils jwtUtils,
                       RefreshTokenService refreshTokenService, TokenBlacklistService blacklistService) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.jwtUtils = jwtUtils;
        this.refreshTokenService = refreshTokenService;
        this.blacklistService = blacklistService;
    }

    // Bài 1: Login -> cấp cặp Access Token + Refresh Token
    public TokenResponseDTO login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password()));

        User user = userRepository.findByUsername(request.username()).orElseThrow();
        String accessToken = jwtUtils.generateAccessToken(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());
        return new TokenResponseDTO(accessToken, refreshToken.getToken(), jwtUtils.getAccessTokenExpiration());
    }

    // Bài 3: Token Rotation
    @Transactional
    public TokenResponseDTO refreshToken(String requestToken) {
        // 1-2. Tìm token trong DB, không có hoặc hết hạn -> exception (403)
        RefreshToken oldToken = refreshTokenService.findByToken(requestToken)
                .orElseThrow(() -> new TokenRefreshException(requestToken, "khong ton tai hoac da bi thu hoi"));
        refreshTokenService.verifyExpiration(oldToken);

        // 3. Rotation: xóa Refresh Token cũ -> mỗi Refresh Token chỉ dùng được 1 lần
        User user = oldToken.getUser();
        refreshTokenService.delete(oldToken);

        // 4-5. Cấp Access Token mới + Refresh Token hoàn toàn mới
        String accessToken = jwtUtils.generateAccessToken(user);
        RefreshToken newToken = refreshTokenService.createRefreshToken(user.getId());

        // 6. Trả về cặp token mới
        return new TokenResponseDTO(accessToken, newToken.getToken(), jwtUtils.getAccessTokenExpiration());
    }

    // Bài 4: Logout -> đưa jti vào blacklist Redis với TTL = thời gian sống còn lại của token
    @Transactional
    public void logout(String accessToken, String refreshToken) {
        // 1. Giải mã lấy jti và exp
        Claims claims = jwtUtils.parseClaims(accessToken);
        String jti = claims.getId();
        Instant exp = claims.getExpiration().toInstant();

        // 2. TTL = exp - now
        Duration ttl = Duration.between(Instant.now(), exp);

        // 3-4. SET blacklist:{jti} "revoked" EX ttl
        if (ttl.isPositive()) {
            blacklistService.blacklist(jti, ttl);
        }

        // 5. Xóa Refresh Token: client gửi kèm thì xóa đúng token đó, không thì xóa hết của user
        if (refreshToken != null && !refreshToken.isBlank()) {
            refreshTokenService.deleteByToken(refreshToken);
        } else {
            userRepository.findByUsername(claims.getSubject()).ifPresent(refreshTokenService::deleteByUser);
        }
    }
}
