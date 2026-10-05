package com.example.identityservice.dto;

import com.example.identityservice.entity.User;

/** Không bao giờ trả password (kể cả đã băm) ra ngoài. */
public record UserResponse(String id, String username, String role) {
    public static UserResponse from(User user) {
        return new UserResponse(user.getId(), user.getUsername(), user.getRole().name());
    }
}
