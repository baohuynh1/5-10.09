package com.example.productservice;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/** Dữ liệu tĩnh trong bộ nhớ (không DB) — trọng tâm là phân quyền. */
@RestController
@RequestMapping("/api/products")
public class ProductController {

    private final List<Product> products = new CopyOnWriteArrayList<>(List.of(
            new Product(1L, "Laptop", new BigDecimal("25000000")),
            new Product(2L, "Chuột không dây", new BigDecimal("350000")),
            new Product(3L, "Bàn phím cơ", new BigDecimal("1200000"))
    ));

    /** Mọi user đã đăng nhập (STUDENT, INSTRUCTOR hoặc ADMIN). */
    @GetMapping
    @PreAuthorize("isAuthenticated()")
    public List<Product> getAll() {
        return products;
    }

    @GetMapping("/{id}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Product> getById(@PathVariable Long id) {
        return products.stream()
                .filter(p -> p.id().equals(id))
                .findFirst()
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /** Chỉ ADMIN. hasRole('ADMIN') == hasAuthority('ROLE_ADMIN') vì filter đã thêm tiền tố ROLE_. */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> delete(@PathVariable Long id, Authentication authentication) {
        boolean removed = products.removeIf(p -> p.id().equals(id));
        if (!removed) {
            return ResponseEntity.status(404).body(Map.of("status", 404, "message", "Không tìm thấy sản phẩm " + id));
        }
        return ResponseEntity.ok(Map.of(
                "status", 200,
                "message", "Đã xóa sản phẩm " + id,
                "deletedBy", authentication.getName()
        ));
    }
}
