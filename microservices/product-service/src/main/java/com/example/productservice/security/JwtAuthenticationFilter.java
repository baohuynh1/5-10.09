package com.example.productservice.security;

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
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.List;

/**
 * "Trạm kiểm soát": chạy 1 lần cho mỗi request.
 * KHÔNG đánh dấu @Component — nếu là bean, Spring Boot sẽ tự đăng ký thêm nó làm servlet filter thường
 * (chạy ngoài Security chain). Filter được tạo bằng new trong SecurityConfig.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String ROLE_CLAIM = "role";

    private final JwtUtils jwtUtils;

    public JwtAuthenticationFilter(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // 1. Lấy JWT từ header "Authorization: Bearer <token>"
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            // Không có token -> để request đi tiếp dạng "chưa xác thực";
            // endpoint cần đăng nhập sẽ bị AuthenticationEntryPoint trả 401.
            filterChain.doFilter(request, response);
            return;
        }
        String token = header.substring(BEARER_PREFIX.length()).trim();

        try {
            // 2. Verify chữ ký (cùng secret với identity-service) + hạn dùng
            Claims claims = jwtUtils.parseClaims(token);

            // 3. Trích xuất username (sub) và role
            String username = claims.getSubject();

            // 4. "ADMIN" -> [ROLE_ADMIN] để dùng được hasRole('ADMIN')
            List<SimpleGrantedAuthority> authorities = extractRoles(claims).stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                    .toList();

            // 5. Tạo Authentication (đã xác thực, không cần credentials) và nạp vào SecurityContext
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(username, null, authorities);
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (JwtException | IllegalArgumentException ex) {
            // Token sai chữ ký / hết hạn / sai định dạng -> chặn luôn với 401
            SecurityContextHolder.clearContext();
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write("{\"status\":401,\"message\":\"Token không hợp lệ hoặc đã hết hạn\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }

    /** Claim "role" là 1 chuỗi, ví dụ "ADMIN". Vẫn chấp nhận dạng mảng nếu sau này đổi sang nhiều role. */
    private List<String> extractRoles(Claims claims) {
        Object raw = claims.get(ROLE_CLAIM);
        if (raw instanceof String single && !single.isBlank()) {
            return List.of(single);
        }
        if (raw instanceof Collection<?> collection) {
            return collection.stream().map(String::valueOf).toList();
        }
        return List.of();
    }
}
