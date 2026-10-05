package com.example.courseservice;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Dữ liệu tĩnh (Java List). Quyền lấy từ header X-User-Role do Gateway gắn,
 * vì vậy service này chỉ được truy cập qua Gateway, không mở port 8083 ra ngoài.
 */
@RestController
@RequestMapping("/api/courses")
public class CourseController {

    private final AtomicLong idSeq = new AtomicLong(3);
    private final List<Course> courses = new CopyOnWriteArrayList<>(List.of(
            new Course(1L, "Spring Boot cơ bản", "thaygiao"),
            new Course(2L, "Microservices với Spring Cloud", "thaygiao"),
            new Course(3L, "Bảo mật API với JWT", "thaygiao")
    ));

    /** Xem danh sách: STUDENT hoặc INSTRUCTOR. Trả kèm thông tin user để kiểm chứng header từ Gateway. */
    @GetMapping
    @PreAuthorize("hasAuthority('STUDENT') or hasAuthority('INSTRUCTOR')")
    public Map<String, Object> getAll(Authentication authentication) {
        return Map.of(
                "currentUser", Map.of(
                        "username", authentication.getName(),
                        "authorities", authentication.getAuthorities().stream()
                                .map(GrantedAuthority::getAuthority).toList()),
                "courses", courses
        );
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('STUDENT') or hasAuthority('INSTRUCTOR')")
    public ResponseEntity<Course> getById(@PathVariable Long id) {
        return courses.stream().filter(c -> c.id().equals(id)).findFirst()
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /** Tạo khóa học: chỉ INSTRUCTOR. STUDENT -> 403 Forbidden. */
    @PostMapping
    @PreAuthorize("hasAuthority('INSTRUCTOR')")
    public ResponseEntity<Course> create(@RequestBody Map<String, String> body, Authentication authentication) {
        Course course = new Course(idSeq.incrementAndGet(),
                body.getOrDefault("title", "Khóa học mới"),
                authentication.getName());
        courses.add(course);
        return ResponseEntity.status(HttpStatus.CREATED).body(course);
    }
}
