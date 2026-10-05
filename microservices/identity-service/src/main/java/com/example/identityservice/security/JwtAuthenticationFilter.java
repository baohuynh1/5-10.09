package com.example.identityservice.security;

import com.example.identityservice.service.TokenBlacklistService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * Xác thực access token cho các endpoint được bảo vệ của identity-service (vd: /api/auth/logout).
 * Ngoài kiểm tra chữ ký + exp, còn kiểm tra jti có nằm trong blacklist (Redis) không.
 * Không phải @Component: được tạo trong SecurityConfig để không bị đăng ký 2 lần.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    /** Endpoint public: bỏ qua filter, kể cả khi client lỡ gửi kèm token cũ/hết hạn. */
    private static final Set<String> PUBLIC_PATHS = Set.of(
            "/api/auth/register", "/api/auth/login", "/api/auth/refresh", "/api/auth/test-token");

    private final JwtUtils jwtUtils;
    private final TokenBlacklistService blacklistService;

    public JwtAuthenticationFilter(JwtUtils jwtUtils, TokenBlacklistService blacklistService) {
        this.jwtUtils = jwtUtils;
        this.blacklistService = blacklistService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return PUBLIC_PATHS.contains(request.getServletPath());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            filterChain.doFilter(request, response); // -> AuthenticationEntryPoint trả 401
            return;
        }

        Claims claims;
        try {
            claims = jwtUtils.parseClaims(header.substring(BEARER_PREFIX.length()).trim());
        } catch (JwtException | IllegalArgumentException ex) {
            unauthorized(response, "Token không hợp lệ hoặc đã hết hạn");
            return;
        }

        // Token còn hạn và đúng chữ ký nhưng đã logout -> chặn
        if (blacklistService.isBlacklisted(claims.getId())) {
            unauthorized(response, "Token đã bị thu hồi (đã đăng xuất)");
            return;
        }

        List<SimpleGrantedAuthority> authorities = extractRoles(claims).stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .toList();
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(claims.getSubject(), null, authorities));

        filterChain.doFilter(request, response);
    }

    /** Claim "role" là 1 chuỗi, ví dụ "INSTRUCTOR". */
    private List<String> extractRoles(Claims claims) {
        Object raw = claims.get(JwtUtils.ROLE_CLAIM);
        if (raw instanceof String role && !role.isBlank()) {
            return List.of(role);
        }
        if (raw instanceof Collection<?> c) {
            return c.stream().map(String::valueOf).toList();
        }
        return List.of();
    }

    private void unauthorized(HttpServletResponse response, String message) throws IOException {
        SecurityContextHolder.clearContext();
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"status\":401,\"message\":\"" + message + "\"}");
    }
}
