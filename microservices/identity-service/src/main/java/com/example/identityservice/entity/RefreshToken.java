package com.example.identityservice.entity;

import jakarta.persistence.*;

import java.time.Instant;

/**
 * Refresh Token = chuỗi ngẫu nhiên (UUID), dài hạn, LƯU TRONG DB (stateful)
 * -> server có thể thu hồi bằng cách xóa bản ghi.
 * ManyToOne: một user có thể đăng nhập trên nhiều thiết bị, mỗi thiết bị một refresh token.
 */
@Entity
@Table(name = "refresh_tokens")
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 36)
    private String token;

    @Column(name = "expiry_date", nullable = false)
    private Instant expiryDate;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    public RefreshToken() {
    }

    public RefreshToken(String token, Instant expiryDate, User user) {
        this.token = token;
        this.expiryDate = expiryDate;
        this.user = user;
    }

    public boolean isExpired() {
        return expiryDate.isBefore(Instant.now());
    }

    public Long getId() { return id; }
    public String getToken() { return token; }
    public Instant getExpiryDate() { return expiryDate; }
    public User getUser() { return user; }
}
