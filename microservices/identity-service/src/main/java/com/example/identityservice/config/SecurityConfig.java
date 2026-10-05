package com.example.identityservice.config;

import com.example.identityservice.security.JwtAuthenticationFilter;
import com.example.identityservice.security.JwtUtils;
import com.example.identityservice.service.TokenBlacklistService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.NullSecurityContextRepository;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtUtils jwtUtils,
                                                   TokenBlacklistService blacklistService) throws Exception {
        http
                // API stateless dùng token trong header -> không cần CSRF
                .csrf(AbstractHttpConfigurer::disable)

                // STATELESS: Spring Security không bao giờ tạo HttpSession / JSESSIONID
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Không lưu SecurityContext giữa các request -> mỗi request độc lập
                .securityContext(ctx -> ctx.securityContextRepository(new NullSecurityContextRepository()))
                .requestCache(AbstractHttpConfigurer::disable)

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/api/auth/register", "/api/auth/login", "/api/auth/refresh").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/auth/test-token").permitAll()
                        .requestMatchers("/error").permitAll()
                        .anyRequest().authenticated()   // gồm POST /api/auth/logout: cần access token hợp lệ
                )

                // Verify JWT + kiểm tra blacklist Redis cho mọi endpoint được bảo vệ
                .addFilterBefore(new JwtAuthenticationFilter(jwtUtils, blacklistService),
                        UsernamePasswordAuthenticationFilter.class)

                // Không dùng form login / basic auth (đều dựa vào session hoặc gửi mật khẩu mỗi request)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable) // tắt LogoutFilter mặc định của Spring (dựa trên session)

                // Request chưa xác thực vào endpoint được bảo vệ -> 401 JSON (mặc định sẽ là 403)
                .exceptionHandling(ex -> ex.authenticationEntryPoint((request, response, authException) -> {
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    response.setCharacterEncoding("UTF-8");
                    response.getWriter().write("{\"status\":401,\"message\":\"Unauthorized\"}");
                }));
        return http.build();
    }

    /** Bean dùng chung: băm mật khẩu khi đăng ký và đối soát (matches) khi đăng nhập. */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
