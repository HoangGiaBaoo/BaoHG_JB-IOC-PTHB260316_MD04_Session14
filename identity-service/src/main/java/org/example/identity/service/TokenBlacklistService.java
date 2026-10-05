package org.example.identity.service;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class TokenBlacklistService {

    public static final String PREFIX = "blacklist:";

    private final StringRedisTemplate redisTemplate;

    public TokenBlacklistService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void blacklist(String jti, Duration ttl) {
        // Key tự xóa khi Access Token hết hạn tự nhiên
        redisTemplate.opsForValue().set(PREFIX + jti, "revoked", ttl);
    }

    public boolean isBlacklisted(String jti) {
        return jti != null && Boolean.TRUE.equals(redisTemplate.hasKey(PREFIX + jti));
    }
}
