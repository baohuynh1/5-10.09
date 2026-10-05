package com.example.identityservice.service;

import com.example.identityservice.dto.AuthResponse;
import com.example.identityservice.dto.LoginRequest;
import com.example.identityservice.dto.RegisterRequest;
import com.example.identityservice.dto.TokenResponse;
import com.example.identityservice.dto.UserResponse;
import com.example.identityservice.entity.RefreshToken;
import com.example.identityservice.entity.Role;
import com.example.identityservice.entity.User;
import com.example.identityservice.exception.TokenRefreshException;
import com.example.identityservice.exception.UserNotFoundException;
import com.example.identityservice.exception.UsernameAlreadyExistsException;
import com.example.identityservice.repository.UserRepository;
import com.example.identityservice.security.JwtUtils;
import io.jsonwebtoken.Claims;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistService tokenBlacklistService;

    /** Hash giả để thời gian xử lý khi không có user ≈ khi sai mật khẩu (chống dò username). */
    private final String dummyHash;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder,
                       JwtUtils jwtUtils, RefreshTokenService refreshTokenService,
                       TokenBlacklistService tokenBlacklistService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtils = jwtUtils;
        this.refreshTokenService = refreshTokenService;
        this.tokenBlacklistService = tokenBlacklistService;
        this.dummyHash = passwordEncoder.encode("dummy-password-for-timing");
    }

    @Transactional
    public UserResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            throw new UsernameAlreadyExistsException(request.username());
        }
        Role role = (request.role() != null) ? Role.valueOf(request.role()) : Role.STUDENT;
        User user = new User(request.username(), passwordEncoder.encode(request.password()), role);
        return UserResponse.from(userRepository.save(user));
    }

    /**
     * Bài 5: đăng nhập -> cấp CẶP token.
     * 1. Xác thực username/password (BCrypt matches).
     * 2. Access Token (JWT, 15 phút).
     * 3. Refresh Token (UUID, 7 ngày, lưu DB).
     */
    @Transactional
    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByUsername(request.username()).orElse(null);
        String encoded = (user != null) ? user.getPassword() : dummyHash;
        boolean matches = passwordEncoder.matches(request.password(), encoded);
        if (user == null || !matches) {
            throw new BadCredentialsException("Bad credentials");
        }

        String accessToken = jwtUtils.generateAccessToken(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());

        return AuthResponse.of(accessToken, refreshToken.getToken(), jwtUtils.getAccessTokenExpirationMs());
    }

    /**
     * Bài 7: Refresh Token Rotation — mỗi refresh token chỉ dùng được ĐÚNG 1 LẦN.
     * Toàn bộ chạy trong 1 transaction: nếu bước tạo token mới lỗi, token cũ không bị mất.
     * noRollbackFor: khi token hết hạn, lệnh xóa token đó vẫn được commit trước khi báo lỗi.
     */
    @Transactional(noRollbackFor = TokenRefreshException.class)
    public AuthResponse refreshToken(String requestToken) {
        // 1. Tìm refresh token trong DB (kèm User sở hữu)
        RefreshToken oldToken = refreshTokenService.findByToken(requestToken)
                // 2a. Không tìm thấy: token giả, hoặc đã bị dùng (đã xóa ở lần rotation trước)
                .orElseThrow(() -> new TokenRefreshException("Refresh token không hợp lệ hoặc đã được sử dụng"));

        // 2b. Hết hạn (expiryDate < now) -> xóa + ném lỗi
        refreshTokenService.verifyExpiration(oldToken);

        User user = oldToken.getUser();

        // 3. ROTATION: xóa token cũ. Nếu 0 dòng bị xóa -> một request khác vừa dùng token này
        if (!refreshTokenService.revoke(oldToken.getToken())) {
            throw new TokenRefreshException("Refresh token không hợp lệ hoặc đã được sử dụng");
        }

        // 4. Access token mới
        String accessToken = jwtUtils.generateAccessToken(user);

        // 5. Refresh token hoàn toàn mới (UUID mới, hạn 7 ngày tính từ bây giờ)
        RefreshToken newToken = refreshTokenService.createRefreshToken(user.getId());

        // 6. Trả cặp token mới
        return AuthResponse.of(accessToken, newToken.getToken(), jwtUtils.getAccessTokenExpirationMs());
    }

    /**
     * Bài 8: Logout tức thì bằng blacklist.
     * accessToken đã được JwtAuthenticationFilter xác thực (đúng chữ ký, còn hạn, chưa bị blacklist).
     */
    public void logout(String accessToken, String refreshToken) {
        // 1. Giải mã lấy jti và exp
        Claims claims = jwtUtils.parseClaims(accessToken);
        String jti = claims.getId();
        Instant exp = claims.getExpiration().toInstant();

        // 2. TTL = exp - now
        Duration ttl = Duration.between(Instant.now(), exp);

        // 3 + 4. SET blacklist:{jti} "revoked" với TTL đúng bằng thời gian sống còn lại
        if (!ttl.isNegative() && !ttl.isZero()) {
            tokenBlacklistService.blacklist(jti, ttl);
        }

        // 5. (Tùy chọn) Hủy refresh token của thiết bị này trong PostgreSQL
        if (refreshToken != null && !refreshToken.isBlank()) {
            refreshTokenService.revokeIfOwnedBy(refreshToken, claims.getSubject());
        }
    }

    /** Bài 2: cấp access token theo username (chỉ để test, không kiểm tra mật khẩu). */
    @Transactional(readOnly = true)
    public TokenResponse generateTestToken(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException(username));
        return new TokenResponse(jwtUtils.generateAccessToken(user), "Bearer",
                jwtUtils.getAccessTokenExpirationMs() / 1000);
    }
}
