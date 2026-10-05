package org.example.identity.config;

import org.example.identity.entity.Role;
import org.example.identity.entity.User;
import org.example.identity.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Tạo sẵn tài khoản test: admin/admin123, staff/staff123, user/user123.
 */
@Component
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        createIfMissing("admin", "admin123", Role.ADMIN);
        createIfMissing("staff", "staff123", Role.STAFF);
        createIfMissing("user", "user123", Role.USER);
    }

    private void createIfMissing(String username, String rawPassword, Role role) {
        if (!userRepository.existsByUsername(username)) {
            userRepository.save(new User(username, passwordEncoder.encode(rawPassword), role));
        }
    }
}
