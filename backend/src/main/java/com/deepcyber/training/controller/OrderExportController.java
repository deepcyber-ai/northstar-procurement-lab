package com.deepcyber.training.controller;

import com.deepcyber.training.api.LabApiException;
import com.deepcyber.training.service.AccessPolicy;
import com.deepcyber.training.service.ExportWorkerService;
import com.deepcyber.training.service.IdentityService;
import com.deepcyber.training.service.VulnerabilityPolicy;
import com.deepcyber.training.store.LabStore;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OrderExportController {
    private final LabStore store;
    private final IdentityService identity;
    private final AccessPolicy access;
    private final VulnerabilityPolicy vulnerabilities;
    private final ExportWorkerService worker;

    public OrderExportController(LabStore store, IdentityService identity, AccessPolicy access,
                                 VulnerabilityPolicy vulnerabilities, ExportWorkerService worker) {
        this.store = store;
        this.identity = identity;
        this.access = access;
        this.vulnerabilities = vulnerabilities;
        this.worker = worker;
    }

    @PostMapping("/api/orders/{id}/export")
    public ExportWorkerService.ExportResult export(@PathVariable String id, @RequestBody ExportRequest body,
                                                   HttpServletRequest request) {
        return run(id, body, request, vulnerabilities.enabled("CMD-01"));
    }

    @PostMapping("/api/secure/orders/{id}/export")
    public ExportWorkerService.ExportResult fixed(@PathVariable String id, @RequestBody ExportRequest body,
                                                  HttpServletRequest request) {
        return run(id, body, request, false);
    }

    private ExportWorkerService.ExportResult run(String id, ExportRequest body, HttpServletRequest request,
                                                  boolean vulnerable) {
        var user = identity.authenticate(request);
        var order = store.findOrder(id).orElseThrow(() -> new LabApiException(HttpStatus.NOT_FOUND,
                "ORDER_NOT_FOUND", "Order was not found"));
        // This containment check is NOT affected by API-01 or the enable-all switch.
        if (!access.canReadOrder(user, order))
            throw new LabApiException(HttpStatus.FORBIDDEN, "ACCESS_DENIED", "The authenticated persona cannot export this order");
        return worker.export(order.getId(), body.format(), vulnerable);
    }

    public record ExportRequest(String format) { }
}
