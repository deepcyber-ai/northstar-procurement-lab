package com.deepcyber.training.controller;

import com.deepcyber.training.api.LabApiException;
import com.deepcyber.training.model.LabRole;
import com.deepcyber.training.model.LabUser;
import com.deepcyber.training.model.OrderRecord;
import com.deepcyber.training.service.AccessPolicy;
import com.deepcyber.training.service.ExportWorkerService;
import com.deepcyber.training.service.IdentityService;
import com.deepcyber.training.service.VulnerabilityPolicy;
import com.deepcyber.training.store.LabStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;

import java.math.BigDecimal;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class OrderExportControllerTests {
    private final LabStore store = mock(LabStore.class);
    private final IdentityService identity = mock(IdentityService.class);
    private final VulnerabilityPolicy flags = mock(VulnerabilityPolicy.class);
    private final ExportWorkerService worker = mock(ExportWorkerService.class);
    private final MockHttpServletRequest request = new MockHttpServletRequest();
    private final OrderExportController controller = new OrderExportController(store, identity, new AccessPolicy(), flags, worker);
    private final LabUser alice = new LabUser("alice", "Alice", "alice@example.test", "tenant-a", "Aster & Row", "Buyer", LabRole.USER);

    @BeforeEach void setup() {
        when(identity.authenticate(request)).thenReturn(alice);
        when(store.findOrder("ORD-A-100")).thenReturn(Optional.of(new OrderRecord("ORD-A-100", "tenant-a", "alice",
                "Untrusted item; never forwarded to shell", 2, BigDecimal.TEN, "DRAFT", 0, 1)));
        when(store.findOrder("ORD-B-100")).thenReturn(Optional.of(new OrderRecord("ORD-B-100", "tenant-b", "bob",
                "Other tenant", 1, BigDecimal.TEN, "DRAFT", 0, 1)));
    }

    @Test void vulnerableFlagIsChosenByServerNotPayload() {
        when(flags.enabled("CMD-01")).thenReturn(true);
        controller.export("ORD-A-100", new OrderExportController.ExportRequest("csv; printf marker"), request);
        verify(worker).export("ORD-A-100", "csv; printf marker", true);
    }

    @Test void disabledFlagUsesFixedPath() {
        when(flags.enabled("CMD-01")).thenReturn(false);
        controller.export("ORD-A-100", new OrderExportController.ExportRequest("csv"), request);
        verify(worker).export("ORD-A-100", "csv", false);
    }

    @Test void secureComparisonIgnoresEnabledVulnerability() {
        when(flags.enabled("CMD-01")).thenReturn(true);
        controller.fixed("ORD-A-100", new OrderExportController.ExportRequest("json"), request);
        verify(worker).export("ORD-A-100", "json", false);
        verifyNoInteractions(flags);
    }

    @Test void crossTenantAccessNeverReachesWorkerEvenWhenAllFlagsAreEnabled() {
        when(flags.enabled(anyString())).thenReturn(true);
        assertThatThrownBy(() -> controller.export("ORD-B-100", new OrderExportController.ExportRequest("csv"), request))
                .isInstanceOfSatisfying(LabApiException.class, error -> assertThat(error.getStatus()).isEqualTo(HttpStatus.FORBIDDEN));
        verifyNoInteractions(worker);
    }

    @Test void unauthenticatedRequestNeverReachesWorkerOrStore() {
        when(identity.authenticate(request)).thenThrow(new LabApiException(HttpStatus.UNAUTHORIZED, "AUTH_REQUIRED", "Sign in"));
        assertThatThrownBy(() -> controller.export("ORD-A-100", new OrderExportController.ExportRequest("csv"), request))
                .isInstanceOfSatisfying(LabApiException.class, error -> assertThat(error.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED));
        verifyNoInteractions(worker, store);
    }

    @Test void unknownOrderDoesNotReachWorker() {
        when(store.findOrder("missing")).thenReturn(Optional.empty());
        assertThatThrownBy(() -> controller.export("missing", new OrderExportController.ExportRequest("csv"), request))
                .isInstanceOfSatisfying(LabApiException.class, error -> assertThat(error.getStatus()).isEqualTo(HttpStatus.NOT_FOUND));
        verifyNoInteractions(worker);
    }
}
