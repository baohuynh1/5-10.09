package com.example.identityservice.dto;

public record TokenResponse(String token, String tokenType, long expiresIn) {
}
