package com.deepcyber.training.api;

import java.time.Instant;

public record ApiError(
        Instant timestamp,
        int status,
        String error,
        String code,
        String message,
        String path,
        boolean trainingOnly
) {
}
