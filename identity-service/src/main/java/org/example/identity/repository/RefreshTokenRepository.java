package org.example.identity.repository;

import org.example.identity.entity.RefreshToken;
import org.example.identity.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    // RefreshToken.user được fetch EAGER nên lấy được luôn User sở hữu token
    Optional<RefreshToken> findByToken(String token);

    @Modifying
    void deleteByUser(User user);

    @Modifying
    void deleteByToken(String token);
}
