package com.deepcyber.training.controller;

import com.deepcyber.training.api.LabApiException;
import com.deepcyber.training.api.WorkflowCallbackRequest;
import com.deepcyber.training.api.WorkflowRequest;
import com.deepcyber.training.model.LabUser;
import com.deepcyber.training.model.OrderRecord;
import com.deepcyber.training.model.WorkflowExecution;
import com.deepcyber.training.service.AccessPolicy;
import com.deepcyber.training.service.IdentityService;
import com.deepcyber.training.service.VulnerabilityPolicy;
import com.deepcyber.training.store.LabStore;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

@RestController
public class WorkflowController {
    private final LabStore store;
    private final IdentityService identityService;
    private final AccessPolicy accessPolicy;
    private final String callbackToken;
    private final VulnerabilityPolicy vulnerabilities;

    public WorkflowController(LabStore store, IdentityService identityService, AccessPolicy accessPolicy,
                              @Value("${lab.callback-token:}") String callbackToken,
                              VulnerabilityPolicy vulnerabilities) {
        this.store = store;
        this.identityService = identityService;
        this.accessPolicy = accessPolicy;
        this.callbackToken = callbackToken;
        this.vulnerabilities = vulnerabilities;
    }

    @PostMapping("/api/workflows")
    public ResponseEntity<WorkflowExecution> vulnerableStart(@Valid @RequestBody WorkflowRequest body,
                                                             HttpServletRequest request) {
        LabUser user = identityService.authenticate(request);
        var flags = vulnerabilities.snapshot();
        if (!flags.get("WF-01")) validateStart(user, body);
        if (!flags.get("WF-02")) return idempotentStart(user, body, request.getHeader("Idempotency-Key"), "/api/workflows/");
        // Each weakness is independently switchable: authorisation does not imply idempotency.
        WorkflowExecution execution = store.createWorkflow(user, body.orderId(), body.action());
        return ResponseEntity.created(URI.create("/api/workflows/" + execution.getId())).body(execution);
    }

    @GetMapping("/api/workflows/{id}")
    public WorkflowExecution vulnerableGet(@PathVariable String id, HttpServletRequest request) {
        if (!vulnerabilities.enabled("WF-03")) return secureGet(id, request);
        identityService.authenticate(request);
        // DELIBERATE IDOR: any authenticated persona can read any workflow.
        return requireWorkflow(id);
    }

    @PostMapping("/api/workflows/{id}/callback")
    public WorkflowExecution vulnerableCallback(@PathVariable String id,
                                                @Valid @RequestBody WorkflowCallbackRequest body,
                                                HttpServletRequest request) {
        if (!vulnerabilities.enabled("WF-04"))
            return secureCallback(id, body, request.getHeader("X-Workflow-Callback-Token"));
        identityService.authenticate(request);
        // DELIBERATE CALLBACK REPLAY: no callback identity and repeated terminal callbacks are accepted.
        return store.callback(id, body.status().toUpperCase(Locale.ROOT), false);
    }

    @PostMapping("/api/secure/workflows")
    public ResponseEntity<WorkflowExecution> secureStart(@Valid @RequestBody WorkflowRequest body,
                                                         @RequestHeader(value = "Idempotency-Key", required = false)
                                                         String idempotencyKey,
                                                         HttpServletRequest request) {
        LabUser user = identityService.authenticate(request);
        validateStart(user, body);
        return idempotentStart(user, body, idempotencyKey, "/api/secure/workflows/");
    }

    private void validateStart(LabUser user, WorkflowRequest body) {
        OrderRecord order = requireOrder(body.orderId());
        if (!accessPolicy.canReadOrder(user, order)) {
            throw forbidden("The authenticated persona cannot start a workflow for this order");
        }
        if (!"SUBMIT_FOR_APPROVAL".equals(body.action())) {
            throw new LabApiException(HttpStatus.BAD_REQUEST, "ACTION_NOT_ALLOWED",
                    "Secure mode only permits SUBMIT_FOR_APPROVAL");
        }
    }

    private ResponseEntity<WorkflowExecution> idempotentStart(LabUser user, WorkflowRequest body,
                                                             String idempotencyKey, String locationPrefix) {
        if (idempotencyKey == null || idempotencyKey.length() < 8 || idempotencyKey.length() > 128) {
            throw new LabApiException(HttpStatus.BAD_REQUEST, "IDEMPOTENCY_KEY_REQUIRED",
                    "Idempotency-Key must contain between 8 and 128 characters");
        }
        LabStore.WorkflowStart result = store.createIdempotentWorkflow(user, body.orderId(), body.action(),
                idempotencyKey);
        return ResponseEntity.status(result.replayed() ? HttpStatus.OK : HttpStatus.CREATED)
                .header("X-Idempotent-Replay", Boolean.toString(result.replayed()))
                .location(URI.create(locationPrefix + result.execution().getId()))
                .body(result.execution());
    }

    @GetMapping("/api/secure/workflows/{id}")
    public WorkflowExecution secureGet(@PathVariable String id, HttpServletRequest request) {
        LabUser user = identityService.authenticate(request);
        WorkflowExecution workflow = requireWorkflow(id);
        OrderRecord order = requireOrder(workflow.getOrderId());
        if (!accessPolicy.canReadOrder(user, order)) {
            throw forbidden("The authenticated persona cannot read this workflow");
        }
        return workflow;
    }

    @PostMapping("/api/secure/workflows/{id}/callback")
    public WorkflowExecution secureCallback(@PathVariable String id,
                                            @Valid @RequestBody WorkflowCallbackRequest body,
                                            @RequestHeader(value = "X-Workflow-Callback-Token", required = false)
                                            String suppliedToken) {
        if (callbackToken.length() < 32)
            throw new LabApiException(HttpStatus.NOT_FOUND, "CALLBACK_DISABLED", "Secure callbacks require a configured service token");
        if (suppliedToken == null || !MessageDigest.isEqual(callbackToken.getBytes(StandardCharsets.UTF_8),
                suppliedToken.getBytes(StandardCharsets.UTF_8))) {
            throw new LabApiException(HttpStatus.UNAUTHORIZED, "INVALID_CALLBACK_TOKEN",
                    "The workflow callback token is missing or invalid");
        }
        String status = body.status().toUpperCase(Locale.ROOT);
        if (!status.equals("COMPLETED") && !status.equals("FAILED")) {
            throw new LabApiException(HttpStatus.BAD_REQUEST, "INVALID_WORKFLOW_STATUS",
                    "Secure callbacks permit only COMPLETED or FAILED");
        }
        return store.callback(id, status, true);
    }

    private OrderRecord requireOrder(String id) {
        return store.findOrder(id)
                .orElseThrow(() -> new LabApiException(HttpStatus.NOT_FOUND, "ORDER_NOT_FOUND", "Order was not found"));
    }

    private WorkflowExecution requireWorkflow(String id) {
        return store.findWorkflow(id)
                .orElseThrow(() -> new LabApiException(HttpStatus.NOT_FOUND, "WORKFLOW_NOT_FOUND", "Workflow was not found"));
    }

    private LabApiException forbidden(String message) {
        return new LabApiException(HttpStatus.FORBIDDEN, "ACCESS_DENIED", message);
    }
}
