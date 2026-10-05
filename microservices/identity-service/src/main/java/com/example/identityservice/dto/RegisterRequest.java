package com.example.identityservice.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank(message = "Username không được để trống")
        @Size(min = 3, max = 50, message = "Username phải từ 3 đến 50 ký tự")
        String username,

        @NotBlank(message = "Password không được để trống")
        @Size(min = 6, message = "Password phải có ít nhất 6 ký tự")
        String password,

        /** Tùy chọn, mặc định STUDENT. Không cho tự đăng ký ADMIN. */
        @Pattern(regexp = "STUDENT|INSTRUCTOR", message = "Role chỉ được là STUDENT hoặc INSTRUCTOR")
        String role
) {
}
