package com.deepcyber.training.controller;

import com.deepcyber.training.api.LabApiException;
import com.deepcyber.training.model.OrderRecord;
import com.deepcyber.training.service.AccessPolicy;
import com.deepcyber.training.service.IdentityService;
import com.deepcyber.training.service.SupplierWidget;
import com.deepcyber.training.service.VulnerabilityPolicy;
import com.deepcyber.training.store.LabStore;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
public class ContentLabController {
    private final LabStore store;
    private final IdentityService identity;
    private final AccessPolicy access;
    private final VulnerabilityPolicy policy;

    public ContentLabController(LabStore store, IdentityService identity, AccessPolicy access, VulnerabilityPolicy policy) {
        this.store = store; this.identity = identity; this.access = access; this.policy = policy;
    }

    @GetMapping("/api/ui-policy")
    public ResponseEntity<Map<String, Object>> uiPolicy(HttpServletRequest request) {
        identity.authenticate(request);
        String before = policy.revision();
        var flags = policy.snapshot();
        String revision = policy.revision();
        // A concurrent owner change must never produce a mixed-generation enabled response.
        boolean consistent = before.equals(revision);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(Map.of(
                "xssEnabled", consistent && Boolean.TRUE.equals(flags.get("XSS-01")),
                "supplyChainEnabled", consistent && Boolean.TRUE.equals(flags.get("SC-01")),
                "revision", revision, "widgetIntegrity", SupplierWidget.INTEGRITY));
    }

    @GetMapping({"/api/orders/{id}/notes", "/api/secure/orders/{id}/notes"})
    public Notes notes(@PathVariable String id, HttpServletRequest request) {
        authorize(id, request, false);
        return new Notes(id, store.orderNotes(id));
    }

    @PutMapping({"/api/orders/{id}/notes", "/api/secure/orders/{id}/notes"})
    public Notes saveNotes(@PathVariable String id, @Valid @RequestBody NotesUpdate update, HttpServletRequest request) {
        authorize(id, request, true);
        // Stored HTML is inert data. XSS-01 is deliberately introduced at the Angular rendering sink.
        // The secure API stores the same data: the fixed UI must still sanitize it when rendering.
        store.saveOrderNotes(id, update.html());
        return new Notes(id, update.html());
    }

    @GetMapping(value="/api/vendor/widget.js", produces="application/javascript;charset=UTF-8")
    public ResponseEntity<String> widget() { return javascript(store.vendorWidget(SupplierWidget.TRUSTED_SCRIPT)); }

    @GetMapping(value="/api/secure/vendor/widget.js", produces="application/javascript;charset=UTF-8")
    public ResponseEntity<String> trustedWidget() { return javascript(SupplierWidget.TRUSTED_SCRIPT); }

    @PutMapping("/api/vendor/widget")
    public Map<String, Boolean> publishWidget(@Valid @RequestBody WidgetUpdate update, HttpServletRequest request) {
        identity.authenticate(request);
        if (!policy.enabled("SC-01")) throw new LabApiException(HttpStatus.FORBIDDEN, "PUBLISHER_DISABLED", "Supplier publishing is not available");
        // DELIBERATE SC-01: any signed-in purchaser can overwrite this lab-owned supplier script.
        // There are no real vendor credentials, packages, registries or upstream services involved.
        store.saveVendorWidget(update.script());
        return Map.of("updated", true);
    }

    private ResponseEntity<String> javascript(String script) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header("X-Content-Type-Options", "nosniff")
                .contentType(MediaType.parseMediaType("application/javascript;charset=UTF-8")).body(script);
    }
    private void authorize(String id, HttpServletRequest request, boolean edit) {
        var user = identity.authenticate(request);
        OrderRecord order = store.findOrder(id).orElseThrow(() -> new LabApiException(HttpStatus.NOT_FOUND, "ORDER_NOT_FOUND", "Order was not found"));
        if (!(edit ? access.canEditOrder(user, order) : access.canReadOrder(user, order)))
            throw new LabApiException(HttpStatus.FORBIDDEN, "ACCESS_DENIED", "You cannot access notes for this order");
    }
    public record Notes(String orderId, String html) { }
    public record NotesUpdate(@NotNull @Size(max=8192) String html) { }
    public record WidgetUpdate(@NotNull @Size(min=1, max=16384) String script) { }
}
