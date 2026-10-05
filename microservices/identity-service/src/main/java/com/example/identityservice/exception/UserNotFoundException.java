package com.example.identityservice.exception;

public class UserNotFoundException extends RuntimeException {
    public UserNotFoundException(String username) {
        super("Không tìm thấy user '" + username + "'");
    }
}
