package org.example.product.controller;

import org.example.product.model.Product;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    // Dữ liệu tĩnh, không dùng Database
    private final List<Product> products = new CopyOnWriteArrayList<>(List.of(
            new Product(1L, "iPhone 16", 25_000_000),
            new Product(2L, "Samsung Galaxy S25", 22_000_000),
            new Product(3L, "Xiaomi 15", 15_000_000)));
    private final AtomicLong idGenerator = new AtomicLong(3);

    // Bài 2: mọi user đã đăng nhập | Bài 6: cần quyền PRODUCT_READ
    @GetMapping
    @PreAuthorize("hasAuthority('PRODUCT_READ')")
    public List<Product> getAll() {
        return products;
    }

    // Bài 6: cần quyền PRODUCT_CREATE
    @PostMapping
    @PreAuthorize("hasAuthority('PRODUCT_CREATE')")
    public ResponseEntity<Product> create(@RequestBody Product request) {
        Product product = new Product(idGenerator.incrementAndGet(), request.name(), request.price());
        products.add(product);
        return ResponseEntity.status(HttpStatus.CREATED).body(product);
    }

    // Bài 2: chỉ ADMIN
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> delete(@PathVariable Long id) {
        boolean removed = products.removeIf(p -> p.id().equals(id));
        if (!removed) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("status", 404, "message", "Khong tim thay san pham " + id));
        }
        return ResponseEntity.ok(Map.of("status", 200, "message", "Da xoa san pham " + id));
    }
}
