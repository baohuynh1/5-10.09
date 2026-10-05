package com.example.identityservice.service;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * Blacklist access token đã logout, lưu trong Redis.
 * Key: blacklist:{jti}  Value: "revoked"  TTL: thời gian sống còn lại của token.
 * Hết TTL, Redis tự xóa key — lúc đó token cũng đã hết hạn tự nhiên nên không cần chặn nữa.
 */
@Service
public class TokenBlacklistService {

    private static final String KEY_PREFIX = "blacklist:";
    private static final String REVOKED = "revoked";

    private final StringRedisTemplate redisTemplate;

    public TokenBlacklistService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void blacklist(String jti, Duration ttl) {
        // SET blacklist:{jti} "revoked" PX <ttl>  (set + expire trong 1 lệnh, nguyên tử)
        redisTemplate.opsForValue().set(KEY_PREFIX + jti, REVOKED, ttl);
    }

    public boolean isBlacklisted(String jti) {
        return jti != null && Boolean.TRUE.equals(redisTemplate.hasKey(KEY_PREFIX + jti));
    }
}
