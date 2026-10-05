package org.example.identity.service;

import org.example.identity.entity.RefreshToken;
import org.example.identity.entity.User;
import org.example.identity.exception.TokenRefreshException;
import org.example.identity.repository.RefreshTokenRepository;
import org.example.identity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final long refreshTokenExpiration;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository,
                               UserRepository userRepository,
                               @Value("${app.jwt.refresh-token-expiration}") long refreshTokenExpiration) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.refreshTokenExpiration = refreshTokenExpiration;
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Transactional
    public RefreshToken createRefreshToken(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + userId));
        RefreshToken refreshToken = new RefreshToken(
                UUID.randomUUID().toString(),
                Instant.now().plusMillis(refreshTokenExpiration),
                user);
        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * Token quá hạn thì xóa khỏi DB và ném exception (403).
     * REQUIRES_NEW để lệnh xóa vẫn được commit dù transaction bên ngoài rollback vì exception.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW, noRollbackFor = TokenRefreshException.class)
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.deleteByToken(token.getToken());
            throw new TokenRefreshException(token.getToken(), "da het han, vui long dang nhap lai");
        }
        return token;
    }

    @Transactional
    public void delete(RefreshToken token) {
        refreshTokenRepository.delete(token);
    }

    @Transactional
    public void deleteByToken(String token) {
        refreshTokenRepository.deleteByToken(token);
    }

    @Transactional
    public void deleteByUser(User user) {
        refreshTokenRepository.deleteByUser(user);
    }
}
