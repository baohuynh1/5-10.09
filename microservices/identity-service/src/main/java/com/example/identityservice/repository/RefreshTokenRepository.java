package com.example.identityservice.repository;

import com.example.identityservice.entity.RefreshToken;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    /** Tìm theo chuỗi token và JOIN lấy luôn User sở hữu (tránh LazyInitializationException). */
    @EntityGraph(attributePaths = "user")
    Optional<RefreshToken> findByToken(String token);

    /**
     * Xóa trực tiếp bằng câu DELETE và trả về số dòng bị xóa.
     * PostgreSQL khóa dòng khi DELETE -> nếu 2 request cùng dùng 1 token đồng thời,
     * chỉ 1 request nhận được 1, request còn lại nhận 0 (=> token đã bị dùng).
     */
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("DELETE FROM RefreshToken rt WHERE rt.token = :token")
    int deleteByToken(@Param("token") String token);
}
