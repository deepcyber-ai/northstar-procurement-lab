package com.deepcyber.training.api;

import org.springframework.http.HttpStatus;

public class LabApiException extends RuntimeException {
    private final HttpStatus status;
    private final String code;

    public LabApiException(HttpStatus status, String code, String message) {
        super(message);
        this.status = status;
        this.code = code;
    }

    public HttpStatus getStatus() { return status; }
    public String getCode() { return code; }
}
