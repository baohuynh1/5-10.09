package com.example.identityservice.service;

import com.example.identityservice.entity.RefreshToken;
import com.example.identityservice.entity.User;
import com.example.identityservice.exception.TokenRefreshException;
import com.example.identityservice.repository.RefreshTokenRepository;
import com.example.identityservice.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final long refreshTokenExpirationMs;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository,
                               UserRepository userRepository,
                               @Value("${app.jwt.refresh-token-expiration}") long refreshTokenExpirationMs) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.refreshTokenExpirationMs = refreshTokenExpirationMs;
    }

    /** Sinh UUID ngẫu nhiên, hạn = now + 7 ngày, lưu DB. */
    @Transactional
    public RefreshToken createRefreshToken(String userId) {
        User user = userRepository.getReferenceById(userId); // chỉ cần khóa ngoại, không cần SELECT user

        RefreshToken refreshToken = new RefreshToken(
                UUID.randomUUID().toString(),
                Instant.now().plusMillis(refreshTokenExpirationMs),
                user
        );
        return refreshTokenRepository.save(refreshToken);
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    /**
     * Còn hạn -> trả lại token. Hết hạn -> xóa khỏi DB và ném lỗi, buộc người dùng đăng nhập lại.
     * noRollbackFor: lệnh xóa token hết hạn vẫn được commit dù ngay sau đó ném exception.
     */
    @Transactional(noRollbackFor = TokenRefreshException.class)
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.isExpired()) {
            refreshTokenRepository.deleteByToken(token.getToken());
            throw new TokenRefreshException("Refresh token đã hết hạn, vui lòng đăng nhập lại");
        }
        return token;
    }

    /**
     * Rotation: hủy refresh token cũ. Trả về false nếu token đã bị request khác dùng/xóa trước đó.
     */
    @Transactional
    public boolean revoke(String token) {
        return refreshTokenRepository.deleteByToken(token) > 0;
    }

    /** Logout: xóa refresh token nếu nó thuộc về đúng user đang đăng xuất. */
    @Transactional
    public void revokeIfOwnedBy(String token, String username) {
        refreshTokenRepository.findByToken(token)
                .filter(rt -> rt.getUser().getUsername().equals(username))
                .ifPresent(rt -> refreshTokenRepository.deleteByToken(rt.getToken()));
    }
}
