package com.deepcyber.training.controller;

import com.deepcyber.training.api.LabApiException;
import com.deepcyber.training.api.OrderMassAssignmentRequest;
import com.deepcyber.training.api.OrderSafeUpdateRequest;
import com.deepcyber.training.model.LabUser;
import com.deepcyber.training.model.OrderRecord;
import com.deepcyber.training.service.AccessPolicy;
import com.deepcyber.training.service.IdentityService;
import com.deepcyber.training.service.VulnerabilityPolicy;
import com.deepcyber.training.store.LabStore;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class OrderController {
    private final LabStore store;
    private final IdentityService identityService;
    private final AccessPolicy accessPolicy;
    private final VulnerabilityPolicy vulnerabilities;

    public OrderController(LabStore store, IdentityService identityService, AccessPolicy accessPolicy,
                           VulnerabilityPolicy vulnerabilities) {
        this.store = store;
        this.identityService = identityService;
        this.accessPolicy = accessPolicy;
        this.vulnerabilities = vulnerabilities;
    }

    @GetMapping("/api/orders")
    public List<OrderRecord> vulnerableList(HttpServletRequest request) {
        if (!vulnerabilities.enabled("API-01")) return secureList(request);
        LabUser user = identityService.authenticate(request);
        // Deliberately incomplete: tenant filtering exists here, encouraging testers to probe detail routes.
        return store.listOrders().stream()
                .filter(order -> order.getTenantId().equals(user.tenantId()))
                .toList();
    }

    @GetMapping("/api/orders/{id}")
    public OrderRecord vulnerableGet(@PathVariable String id, HttpServletRequest request) {
        if (!vulnerabilities.enabled("API-01")) return secureGet(id, request);
        identityService.authenticate(request);
        // DELIBERATE IDOR: authentication is checked, but tenant and ownership are not.
        return requireOrder(id);
    }

    @PatchMapping("/api/orders/{id}")
    public OrderRecord vulnerableMassAssignment(@PathVariable String id,
                                                @RequestBody OrderMassAssignmentRequest update,
                                                HttpServletRequest request) {
        if (!vulnerabilities.enabled("API-02")) {
            if (update.tenantId() != null || update.ownerId() != null || update.unitPrice() != null || update.status() != null)
                throw new LabApiException(HttpStatus.BAD_REQUEST, "INVALID_REQUEST", "Protected properties cannot be updated");
            return secureUpdate(id, new OrderSafeUpdateRequest(update.item(), update.quantity()), request);
        }
        LabUser user = identityService.authenticate(request);
        OrderRecord existing = requireOrder(id);
        if (!user.id().equals(existing.getOwnerId())) {
            throw forbidden("The vulnerable mass-assignment exercise is limited to the current owner's order");
        }
        // DELIBERATE MASS ASSIGNMENT: protected ownership, tenant, price and status fields are accepted.
        return store.updateOrder(id, order -> {
            if (update.tenantId() != null) order.setTenantId(update.tenantId());
            if (update.ownerId() != null) order.setOwnerId(update.ownerId());
            if (update.item() != null) order.setItem(update.item());
            if (update.quantity() != null) order.setQuantity(update.quantity());
            if (update.unitPrice() != null) order.setUnitPrice(update.unitPrice());
            if (update.status() != null) order.setStatus(update.status());
        });
    }

    @GetMapping("/api/secure/orders")
    public List<OrderRecord> secureList(HttpServletRequest request) {
        LabUser user = identityService.authenticate(request);
        return store.listOrders().stream()
                .filter(order -> accessPolicy.canReadOrder(user, order))
                .toList();
    }

    @GetMapping("/api/secure/orders/{id}")
    public OrderRecord secureGet(@PathVariable String id, HttpServletRequest request) {
        LabUser user = identityService.authenticate(request);
        OrderRecord order = requireOrder(id);
        if (!accessPolicy.canReadOrder(user, order)) {
            throw forbidden("The authenticated persona cannot access this order");
        }
        return order;
    }

    @PatchMapping("/api/secure/orders/{id}")
    public OrderRecord secureUpdate(@PathVariable String id,
                                    @Valid @RequestBody OrderSafeUpdateRequest update,
                                    HttpServletRequest request) {
        LabUser user = identityService.authenticate(request);
        // The ordinary route delegates here without MVC method-parameter validation.
        if ((update.item() != null && (update.item().length() < 3 || update.item().length() > 80))
                || (update.quantity() != null && (update.quantity() < 1 || update.quantity() > 100)))
            throw new LabApiException(HttpStatus.BAD_REQUEST, "VALIDATION_FAILED", "Invalid editable order fields");
        OrderRecord order = requireOrder(id);
        if (!accessPolicy.canEditOrder(user, order)) {
            throw forbidden("Only the owning user can edit this draft order");
        }
        if (!"DRAFT".equals(order.getStatus())) {
            throw new LabApiException(HttpStatus.CONFLICT, "ORDER_NOT_EDITABLE",
                    "Only draft orders may be edited");
        }
        if (update.item() == null && update.quantity() == null) {
            throw new LabApiException(HttpStatus.BAD_REQUEST, "EMPTY_UPDATE", "At least one editable field is required");
        }
        return store.updateOrder(id, current -> {
            if (update.item() != null) current.setItem(update.item());
            if (update.quantity() != null) current.setQuantity(update.quantity());
        });
    }

    private OrderRecord requireOrder(String id) {
        return store.findOrder(id)
                .orElseThrow(() -> new LabApiException(HttpStatus.NOT_FOUND, "ORDER_NOT_FOUND", "Order was not found"));
    }

    private LabApiException forbidden(String message) {
        return new LabApiException(HttpStatus.FORBIDDEN, "ACCESS_DENIED", message);
    }
}
