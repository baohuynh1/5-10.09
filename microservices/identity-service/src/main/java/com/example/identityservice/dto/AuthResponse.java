package com.example.identityservice.dto;

/** Cặp token trả về sau khi đăng nhập / làm mới. expiresIn: số giây sống của accessToken. */
public record AuthResponse(String accessToken, String refreshToken, String tokenType, long expiresIn) {

    public static AuthResponse of(String accessToken, String refreshToken, long accessTokenExpirationMs) {
        return new AuthResponse(accessToken, refreshToken, "Bearer", accessTokenExpirationMs / 1000);
    }
}
