package com.example.identityservice.controller;

import com.example.identityservice.dto.*;
import com.example.identityservice.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
    }

    /** Trả về { accessToken, refreshToken, tokenType, expiresIn }. */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    /** Public (permitAll) vì lúc gọi API này access token thường đã hết hạn. Body: { "refreshToken": "<uuid>" } */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refreshToken(request.refreshToken()));
    }

    /**
     * Cần header "Authorization: Bearer <accessToken>" hợp lệ (đã qua JwtAuthenticationFilter).
     * Body tùy chọn: { "refreshToken": "<uuid>" } để hủy luôn refresh token.
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
            @RequestBody(required = false) LogoutRequest request) {
        String accessToken = authorization.substring("Bearer ".length()).trim();
        authService.logout(accessToken, request != null ? request.refreshToken() : null);
        return ResponseEntity.ok(Map.of("status", 200, "message", "Đăng xuất thành công"));
    }

    @GetMapping("/test-token")
    public ResponseEntity<TokenResponse> testToken(@RequestParam String username) {
        return ResponseEntity.ok(authService.generateTestToken(username));
    }
}
