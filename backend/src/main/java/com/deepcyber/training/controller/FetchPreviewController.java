package com.deepcyber.training.controller;

import com.deepcyber.training.api.FetchPreviewRequest;
import com.deepcyber.training.api.FetchPreviewResponse;
import com.deepcyber.training.service.IdentityService;
import com.deepcyber.training.service.MockFetchService;
import com.deepcyber.training.service.VulnerabilityPolicy;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class FetchPreviewController {
    private final IdentityService identityService;
    private final MockFetchService fetchService;
    private final VulnerabilityPolicy vulnerabilities;

    public FetchPreviewController(IdentityService identityService, MockFetchService fetchService,
                                  VulnerabilityPolicy vulnerabilities) {
        this.identityService = identityService;
        this.fetchService = fetchService;
        this.vulnerabilities = vulnerabilities;
    }

    @PostMapping("/api/tools/fetch-preview")
    public FetchPreviewResponse vulnerableFetch(@Valid @RequestBody FetchPreviewRequest body,
                                                HttpServletRequest request) {
        identityService.authenticate(request);
        return vulnerabilities.enabled("API-03") ? fetchService.unsafeFetch(body.url()) : fetchService.allowlistedFetch(body.url());
    }

    @PostMapping("/api/secure/tools/fetch-preview")
    public FetchPreviewResponse secureFetch(@Valid @RequestBody FetchPreviewRequest body,
                                            HttpServletRequest request) {
        identityService.authenticate(request);
        return fetchService.allowlistedFetch(body.url());
    }
}
