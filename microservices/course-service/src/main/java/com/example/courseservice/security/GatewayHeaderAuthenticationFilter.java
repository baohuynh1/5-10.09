package com.example.courseservice.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Dựng Authentication từ header do Gateway gắn (Gateway đã verify JWT):
 *   X-User-Role: INSTRUCTOR  -> authority "INSTRUCTOR" (KHÔNG thêm tiền tố ROLE_, vì dùng hasAuthority)
 *   X-User-Name: thaygiao    -> principal
 * Không có header -> request là anonymous -> endpoint được bảo vệ trả 401.
 *
 * Không đánh dấu @Component để Spring Boot không đăng ký thêm nó như servlet filter thường.
 */
public class GatewayHeaderAuthenticationFilter extends OncePerRequestFilter {

    public static final String USER_ROLE_HEADER = "X-User-Role";
    public static final String USER_NAME_HEADER = "X-User-Name";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String role = request.getHeader(USER_ROLE_HEADER);

        if (role != null && !role.isBlank()) {
            String username = request.getHeader(USER_NAME_HEADER);
            var authentication = new UsernamePasswordAuthenticationToken(
                    (username != null && !username.isBlank()) ? username : "unknown",
                    null,
                    List.of(new SimpleGrantedAuthority(role.trim())));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        filterChain.doFilter(request, response);
    }
}
