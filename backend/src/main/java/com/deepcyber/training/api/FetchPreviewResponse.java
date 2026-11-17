package com.deepcyber.training.api;

public record FetchPreviewResponse(
        String requestedUrl,
        String resolvedHost,
        int simulatedStatus,
        String body,
        boolean networkAccessPerformed,
        String warning
) {
}
