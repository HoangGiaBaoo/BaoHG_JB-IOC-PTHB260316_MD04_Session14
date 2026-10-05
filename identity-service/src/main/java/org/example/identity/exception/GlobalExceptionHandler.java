package org.example.identity.exception;

import org.example.identity.dto.MessageResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    // Bài 3: Refresh Token không tồn tại / hết hạn / đã bị rotate -> 403
    @ExceptionHandler(TokenRefreshException.class)
    public ResponseEntity<MessageResponse> handleTokenRefresh(TokenRefreshException ex) {
        return build(HttpStatus.FORBIDDEN, ex.getMessage());
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<MessageResponse> handleAuthentication(AuthenticationException ex) {
        return build(HttpStatus.UNAUTHORIZED, "Sai username hoặc password");
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<MessageResponse> handleValidation(MethodArgumentNotValidException ex) {
        return build(HttpStatus.BAD_REQUEST, "Dữ liệu không hợp lệ");
    }

    private ResponseEntity<MessageResponse> build(HttpStatus status, String message) {
        return ResponseEntity.status(status).body(new MessageResponse(status.value(), message));
    }
}
