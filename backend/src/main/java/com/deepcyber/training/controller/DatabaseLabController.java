package com.deepcyber.training.controller;

import com.deepcyber.training.api.LabApiException;
import com.deepcyber.training.model.OrderRecord;
import com.deepcyber.training.service.IdentityService;
import com.deepcyber.training.service.VulnerabilityPolicy;
import com.deepcyber.training.store.LabStore;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;

/** Explicitly opt-in exercises. Management credentials are never stored in SQLite. */
@RestController
@ConditionalOnProperty(name = "lab.training-mode", havingValue = "true")
public class DatabaseLabController {
    private final LabStore store;
    private final IdentityService identities;
    private final String resetToken;
    private final VulnerabilityPolicy vulnerabilities;
    public DatabaseLabController(LabStore store, IdentityService identities,
                                 @Value("${lab.reset-token:}") String resetToken, VulnerabilityPolicy vulnerabilities) {
        this.store = store;
        this.identities = identities;
        this.resetToken = resetToken;
        this.vulnerabilities = vulnerabilities;
    }

    @GetMapping("/api/debug/database-config")
    public Map<String, Object> exposedConfig(@RequestHeader(value="X-Lab-Reset-Token", required=false) String token) {
        if (!vulnerabilities.enabled("DB-01")) requireManagementToken(token);
        return metadata();
    }
    private Map<String, Object> metadata() {
        // DELIBERATE MISCONFIGURATION: no authentication. Strictly allowlisted synthetic metadata.
        return Map.of("engine", "SQLite", "database", "northstar.db", "logicalLocation", "lab-data/northstar.db",
                "schemaVersion", 3, "tables", List.of("users", "orders", "workflows", "idempotency", "metadata", "order_notes", "vendor_widget"));
    }
    @GetMapping("/api/secure/debug/database-config")
    public Map<String, Object> protectedConfig(@RequestHeader(value="X-Lab-Reset-Token", required=false) String token) {
        requireManagementToken(token);
        return metadata();
    }

    @GetMapping("/api/orders/search")
    public List<OrderRecord> search(@RequestParam(defaultValue="") String q, HttpServletRequest request) {
        return store.search(identities.authenticate(request), bounded(q), !vulnerabilities.enabled("SQL-01"));
    }
    @GetMapping("/api/secure/orders/search")
    public List<OrderRecord> safeSearch(@RequestParam(defaultValue="") String q, HttpServletRequest request) {
        return store.search(identities.authenticate(request), bounded(q), true);
    }
    @PostMapping("/api/orders/submit")
    public Map<String, Integer> submit(@Valid @RequestBody SubmitOrder body, HttpServletRequest request) {
        return Map.of("updated", store.changeStatus(identities.authenticate(request), body.orderId(), "PENDING_APPROVAL", !vulnerabilities.enabled("SQL-02")));
    }
    @PostMapping("/api/secure/orders/submit")
    public Map<String, Integer> safeSubmit(@Valid @RequestBody SubmitOrder body, HttpServletRequest request) {
        return Map.of("updated", store.changeStatus(identities.authenticate(request), body.orderId(), "PENDING_APPROVAL", true));
    }
    @PostMapping("/api/lab/reset")
    public Map<String, Object> reset(
            @RequestHeader(value="X-Lab-Reset-Token", required=false) String token,
            @RequestHeader(value="X-Lab-Confirm-Reset", required=false) String confirmation) {
        requireManagementToken(token);
        if (!"RESET-SYNTHETIC-DATA".equals(confirmation))
            throw new LabApiException(HttpStatus.BAD_REQUEST, "RESET_CONFIRMATION_REQUIRED", "Explicit reset confirmation required");
        store.reset();
        return Map.of("reset", true, "seedVersion", 1);
    }
    private void requireManagementToken(String supplied) {
        // Fail closed if not configured or too short; no default secret or bearer fallback.
        if (resetToken.length() < 32)
            throw new LabApiException(HttpStatus.NOT_FOUND, "MANAGEMENT_DISABLED", "Lab management is disabled");
        if (supplied == null || !MessageDigest.isEqual(resetToken.getBytes(StandardCharsets.UTF_8), supplied.getBytes(StandardCharsets.UTF_8)))
            throw new LabApiException(HttpStatus.UNAUTHORIZED, "INVALID_MANAGEMENT_TOKEN", "Lab management token required");
    }
    private String bounded(String q) {
        if (q.length() > 256) throw new LabApiException(HttpStatus.BAD_REQUEST, "QUERY_TOO_LONG", "Query exceeds 256 characters");
        return q;
    }
    public record SubmitOrder(@NotBlank @Size(max=256) String orderId) { }
}
