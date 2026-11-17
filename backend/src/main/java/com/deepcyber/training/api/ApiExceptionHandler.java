package com.deepcyber.training.api;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;

@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(LabApiException.class)
    ResponseEntity<ApiError> handleLabError(LabApiException exception, HttpServletRequest request) {
        return response(exception.getStatus(), exception.getCode(), exception.getMessage(), request);
    }

    @ExceptionHandler({MethodArgumentNotValidException.class, HttpMessageNotReadableException.class})
    ResponseEntity<ApiError> handleInvalidInput(Exception exception, HttpServletRequest request) {
        String message = exception instanceof MethodArgumentNotValidException validation
                ? validation.getBindingResult().getFieldErrors().stream()
                    .findFirst()
                    .map(error -> error.getField() + ": " + error.getDefaultMessage())
                    .orElse("Request validation failed")
                : "Malformed JSON or an unsupported field was supplied";
        return response(HttpStatus.BAD_REQUEST, "INVALID_REQUEST", message, request);
    }

    private ResponseEntity<ApiError> response(HttpStatus status, String code, String message,
                                               HttpServletRequest request) {
        return ResponseEntity.status(status).body(new ApiError(
                Instant.now(), status.value(), status.getReasonPhrase(), code, message,
                request.getRequestURI(), true));
    }
}
