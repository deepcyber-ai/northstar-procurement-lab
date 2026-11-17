package com.deepcyber.training.service;

import com.deepcyber.training.api.FetchPreviewResponse;
import com.deepcyber.training.api.LabApiException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.net.URI;

/**
 * A deterministic SSRF simulator. This class deliberately contains no HTTP or DNS client and
 * never performs network access. It models the security decision without creating a pivot.
 */
@Service
public class MockFetchService {
    private static final String WARNING = "SIMULATED RESPONSE ONLY - NO NETWORK ACCESS WAS PERFORMED";

    public FetchPreviewResponse unsafeFetch(String rawUrl) {
        URI uri = parse(rawUrl);
        String host = uri.getHost() == null ? "unparsed-host" : uri.getHost().toLowerCase();
        String body;
        if (host.equals("metadata.internal") || host.equals("169.254.169.254")) {
            body = "{\"role\":\"training-role\",\"token\":\"FAKE-TRAINING-TOKEN-NOT-A-SECRET\"}";
        } else if (host.equals("orders.internal")) {
            body = "{\"service\":\"orders\",\"diagnostics\":\"TRAINING-ONLY\"}";
        } else {
            body = "SIMULATED PUBLIC PREVIEW FOR " + rawUrl;
        }
        return new FetchPreviewResponse(rawUrl, host, 200, body, false, WARNING);
    }

    public FetchPreviewResponse allowlistedFetch(String rawUrl) {
        URI uri = parse(rawUrl);
        boolean valid = "https".equalsIgnoreCase(uri.getScheme())
                && "public.example.test".equalsIgnoreCase(uri.getHost())
                && uri.getPort() == -1
                && uri.getUserInfo() == null
                && uri.getPath() != null
                && uri.getPath().startsWith("/assets/");
        if (!valid) {
            throw new LabApiException(HttpStatus.BAD_REQUEST, "URL_NOT_ALLOWLISTED",
                    "Only https://public.example.test/assets/* is allowed in secure mode");
        }
        return new FetchPreviewResponse(rawUrl, uri.getHost(), 200,
                "SIMULATED ALLOWLISTED PUBLIC ASSET", false, WARNING);
    }

    private URI parse(String rawUrl) {
        try {
            URI uri = URI.create(rawUrl);
            if (uri.getScheme() == null) {
                throw new IllegalArgumentException("scheme required");
            }
            return uri;
        } catch (IllegalArgumentException exception) {
            throw new LabApiException(HttpStatus.BAD_REQUEST, "INVALID_URL", "A valid absolute URL is required");
        }
    }
}
