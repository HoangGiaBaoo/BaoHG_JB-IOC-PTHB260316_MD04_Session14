package org.example.identity.entity;

import java.util.List;

/**
 * Mỗi Role gom một nhóm Permission (PBAC - Bài 6).
 */
public enum Role {
    ADMIN(List.of("PRODUCT_READ", "PRODUCT_CREATE", "PRODUCT_DELETE")),
    STAFF(List.of("PRODUCT_READ")),
    USER(List.of("PRODUCT_READ"));

    private final List<String> permissions;

    Role(List<String> permissions) {
        this.permissions = permissions;
    }

    public List<String> getPermissions() {
        return permissions;
    }
}
