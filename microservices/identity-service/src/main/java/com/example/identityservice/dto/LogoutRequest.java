package com.example.identityservice.dto;

/** Body tùy chọn của /logout: gửi kèm refreshToken của thiết bị này để hủy luôn trong PostgreSQL. */
public record LogoutRequest(String refreshToken) {
}
