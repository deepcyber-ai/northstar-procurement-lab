package com.deepcyber.training.controller;

import com.deepcyber.training.api.AdminOverview;
import com.deepcyber.training.api.LabApiException;
import com.deepcyber.training.model.LabRole;
import com.deepcyber.training.model.LabUser;
import com.deepcyber.training.model.OrderRecord;
import com.deepcyber.training.model.WorkflowExecution;
import com.deepcyber.training.service.IdentityService;
import com.deepcyber.training.service.VulnerabilityPolicy;
import com.deepcyber.training.store.LabStore;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigDecimal;
import java.util.List;

@RestController
public class AdminController {
    private final LabStore store;
    private final IdentityService identityService;
    private final VulnerabilityPolicy vulnerabilities;

    public AdminController(LabStore store, IdentityService identityService, VulnerabilityPolicy vulnerabilities) {
        this.store = store;
        this.identityService = identityService;
        this.vulnerabilities = vulnerabilities;
    }

    @GetMapping({"/api/admin", "/api/admin/overview"})
    public AdminOverview vulnerableOverview(HttpServletRequest request) {
        LabUser user = identityService.authenticate(request);
        // Nginx always covers the exact root; GW-02 controls whether the subtree is covered too.
        boolean nginx = "nginx".equals(request.getHeader("X-Lab-Gateway"));
        if (nginx && ("/api/admin".equals(request.getRequestURI()) || !vulnerabilities.enabled("GW-02"))
                && user.role() != LabRole.ADMIN) throw forbidden("Gateway admin policy requires a seeded ADMIN identity");
        if (!vulnerabilities.enabled("GW-01")) return secureOverview(request);
        // DELIBERATE AUTHORIZATION FLAW: a gateway-derived, attacker-influenced header is trusted as identity.
        String assertedRole = request.getHeader("X-Authenticated-Role");
        if (!"ADMIN".equalsIgnoreCase(assertedRole)) {
            throw forbidden("X-Authenticated-Role did not assert ADMIN");
        }
        return overview(user, store.listUsers(), store.listOrders(), store.listWorkflows(),
                "all-tenants", "X-Authenticated-Role (deliberately unsafe)");
    }

    @GetMapping("/api/secure/admin/overview")
    public AdminOverview secureOverview(HttpServletRequest request) {
        LabUser user = identityService.authenticate(request);
        if (user.role() != LabRole.ADMIN) {
            throw forbidden("The authenticated persona does not have the ADMIN role");
        }
        List<LabUser> users = store.listUsers().stream()
                .filter(candidate -> candidate.tenantId().equals(user.tenantId()))
                .toList();
        List<OrderRecord> orders = store.listOrders().stream()
                .filter(order -> order.getTenantId().equals(user.tenantId()))
                .toList();
        List<WorkflowExecution> workflows = store.listWorkflows().stream()
                .filter(workflow -> workflow.getTenantId().equals(user.tenantId()))
                .toList();
        return overview(user, users, orders, workflows,
                "tenant:" + user.tenantId(), "seeded authenticated identity");
    }

    private AdminOverview overview(LabUser user, List<LabUser> users, List<OrderRecord> orders,
                                   List<WorkflowExecution> workflows, String scope, String source) {
        BigDecimal total = orders.stream()
                .map(OrderRecord::getTotal)
                .reduce(BigDecimal.ZERO, BigDecimal::add);
        return new AdminOverview(user.id(), scope, source, users.size(), orders.size(), workflows.size(), total, true);
    }

    private LabApiException forbidden(String message) {
        return new LabApiException(HttpStatus.FORBIDDEN, "ADMIN_REQUIRED", message);
    }
}
