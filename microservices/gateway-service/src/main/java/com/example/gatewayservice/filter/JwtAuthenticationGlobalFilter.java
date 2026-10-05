package com.example.gatewayservice.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.List;

/**
 * Kiểm tra JWT ngay tại cổng: request sai/hết hạn bị chặn ở Gateway, không bao giờ tới service phía sau.
 * Token hợp lệ -> gắn X-User-Role (và X-User-Name) rồi forward.
 */
@Component
public class JwtAuthenticationGlobalFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationGlobalFilter.class);

    public static final String USER_ROLE_HEADER = "X-User-Role";
    public static final String USER_NAME_HEADER = "X-User-Name";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String ROLE_CLAIM = "role";

    private final Key signingKey;
    private final List<String> securedPaths;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public JwtAuthenticationGlobalFilter(@Value("${app.jwt.secret}") String secret,
                                         @Value("${app.gateway.secured-paths}") List<String> securedPaths) {
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.securedPaths = securedPaths;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // GlobalFilter chạy cho MỌI route -> chỉ kiểm tra các path được cấu hình bảo vệ
        if (!isSecured(path)) {
            return chain.filter(exchange);
        }

        // 1. Lấy token từ "Authorization: Bearer <token>"
        String header = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            return unauthorized(exchange, "Thiếu Access Token");
        }
        String token = header.substring(BEARER_PREFIX.length()).trim();

        // 2. Verify chữ ký + exp bằng secret dùng chung với identity-service
        Claims claims;
        try {
            claims = Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException ex) {
            return unauthorized(exchange, "Access Token đã hết hạn");
        } catch (JwtException | IllegalArgumentException ex) {
            return unauthorized(exchange, "Access Token không hợp lệ");
        }

        // 3. Trích xuất role
        Object role = claims.get(ROLE_CLAIM);
        if (role == null) {
            return unauthorized(exchange, "Access Token không chứa role");
        }

        // 4. Gắn header mới rồi forward. Xóa trước mọi X-User-* client tự gửi lên để chống giả mạo.
        ServerHttpRequest mutated = request.mutate()
                .headers(h -> {
                    h.remove(USER_ROLE_HEADER);
                    h.remove(USER_NAME_HEADER);
                    h.set(USER_ROLE_HEADER, String.valueOf(role));
                    h.set(USER_NAME_HEADER, claims.getSubject());
                })
                .build();

        log.debug("JWT hợp lệ: user={}, role={}, path={}", claims.getSubject(), role, path);
        return chain.filter(exchange.mutate().request(mutated).build());
    }

    /** Chạy sớm, trước các filter định tuyến của Gateway. */
    @Override
    public int getOrder() {
        return -1;
    }

    private boolean isSecured(String path) {
        return securedPaths.stream().anyMatch(pattern -> pathMatcher.match(pattern.trim(), path));
    }

    /** Chặn ngay tại Gateway với 401 + JSON, không forward xuống service. */
    private Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        String body = "{\"status\":401,\"message\":\"" + message + "\"}";
        DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }
}
