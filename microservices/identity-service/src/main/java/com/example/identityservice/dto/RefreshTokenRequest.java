package com.example.identityservice.dto;

import jakarta.validation.constraints.NotBlank;

public record RefreshTokenRequest(
        @NotBlank(message = "refreshToken không được để trống")
        String refreshToken
) {
}
