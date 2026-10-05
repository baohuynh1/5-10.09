package com.example.productservice.config;

import com.example.productservice.security.JwtAuthenticationFilter;
import com.example.productservice.security.JwtUtils;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity // bật @PreAuthorize / @PostAuthorize
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtUtils jwtUtils) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/error").permitAll()
                        .anyRequest().authenticated()   // mọi API đều cần JWT; phân quyền chi tiết dùng @PreAuthorize
                )

                // Đăng ký "trạm kiểm soát" JWT trước UsernamePasswordAuthenticationFilter
                .addFilterBefore(new JwtAuthenticationFilter(jwtUtils), UsernamePasswordAuthenticationFilter.class)

                .exceptionHandling(ex -> ex
                        // Chưa đăng nhập (không gửi token) -> 401
                        .authenticationEntryPoint((req, res, e) ->
                                writeJson(res, HttpStatus.UNAUTHORIZED, "Unauthorized: thiếu Access Token"))
                        // Đã đăng nhập nhưng không đủ quyền (@PreAuthorize thất bại) -> 403
                        .accessDeniedHandler((req, res, e) ->
                                writeJson(res, HttpStatus.FORBIDDEN, "Forbidden: bạn không có quyền thực hiện thao tác này"))
                );
        return http.build();
    }

    /**
     * Resource Server không có user nào cả. Khai báo bean rỗng để Spring Boot
     * không tự tạo "user" với mật khẩu ngẫu nhiên (và in cảnh báo) khi khởi động.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager();
    }

    private static void writeJson(HttpServletResponse res, HttpStatus status, String message) throws IOException {
        res.setStatus(status.value());
        res.setContentType(MediaType.APPLICATION_JSON_VALUE);
        res.setCharacterEncoding("UTF-8");
        res.getWriter().write("{\"status\":" + status.value() + ",\"message\":\"" + message + "\"}");
    }
}
