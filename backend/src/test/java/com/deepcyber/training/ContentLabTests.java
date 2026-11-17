package com.deepcyber.training;

import com.deepcyber.training.service.SupplierWidget;
import com.deepcyber.training.service.VulnerabilityPolicy;
import com.deepcyber.training.store.LabStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties={"lab.training-mode=true"})
@AutoConfigureMockMvc
class ContentLabTests extends OAuthTestSupport {
    @Autowired MockMvc mvc;
    @Autowired LabStore store;
    @Autowired ObjectMapper json;
    @MockitoBean VulnerabilityPolicy policy;

    @BeforeEach void seed() {
        store.reset();
        when(policy.enabled(anyString())).thenReturn(true);
        when(policy.revision()).thenReturn("content-test-revision");
        when(policy.snapshot()).thenAnswer(invocation -> Map.of("XSS-01", policy.enabled("XSS-01"), "SC-01", policy.enabled("SC-01")));
    }

    @Test void policyIsAuthenticatedReadOnlyAndContainsNoOwnerControls() throws Exception {
        mvc.perform(get("/api/ui-policy")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/ui-policy").header("Authorization", bearer("alice")))
                .andExpect(status().isOk()).andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.xssEnabled").value(true))
                .andExpect(jsonPath("$.supplyChainEnabled").value(true))
                .andExpect(jsonPath("$.widgetIntegrity").value(SupplierWidget.INTEGRITY))
                .andExpect(jsonPath("$.revision").value("content-test-revision"))
                .andExpect(jsonPath("$.ownerPassword").doesNotExist())
                .andExpect(jsonPath("$.flags").doesNotExist());
        mvc.perform(put("/api/ui-policy").header("Authorization", bearer("alice"))
                .contentType(MediaType.APPLICATION_JSON).content("{\"xssEnabled\":true}"))
                .andExpect(status().isMethodNotAllowed());
        when(policy.enabled("XSS-01")).thenReturn(false);
        when(policy.enabled("SC-01")).thenReturn(false);
        mvc.perform(get("/api/ui-policy").header("Authorization", bearer("alice")))
                .andExpect(status().isOk()).andExpect(jsonPath("$.xssEnabled").value(false))
                .andExpect(jsonPath("$.supplyChainEnabled").value(false));
    }

    @Test void notesPersistLiteralMarkupButAlwaysEnforceOwnership() throws Exception {
        String marker = "<img src=x onerror=\"document.body.dataset.northstarXss='seen'\">";
        String body = json.writeValueAsString(Map.of("html", marker));
        mvc.perform(put("/api/orders/ORD-A-100/notes").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isUnauthorized());
        mvc.perform(put("/api/orders/ORD-A-100/notes").header("Authorization", bearer("bob"))
                .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isForbidden());
        mvc.perform(get("/api/orders/ORD-A-100/notes").header("Authorization", bearer("bob")))
                .andExpect(status().isForbidden());
        mvc.perform(put("/api/orders/ORD-A-100/notes").header("Authorization", bearer("alice"))
                .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk()).andExpect(jsonPath("$.html").value(marker));
        mvc.perform(get("/api/orders/ORD-A-100/notes").header("Authorization", bearer("admin-a")))
                .andExpect(status().isOk()).andExpect(jsonPath("$.html").value(marker));
        mvc.perform(put("/api/orders/ORD-A-100/notes").header("Authorization", bearer("admin-a"))
                .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isForbidden());
        // Fixed mode is a sink-level correction; storing data never opts it into trusted HTML.
        when(policy.enabled("XSS-01")).thenReturn(false);
        mvc.perform(get("/api/secure/orders/ORD-A-100/notes").header("Authorization", bearer("alice")))
                .andExpect(status().isOk()).andExpect(jsonPath("$.html").value(marker));
        mvc.perform(put("/api/secure/orders/ORD-A-100/notes").header("Authorization", bearer("bob"))
                .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isForbidden());
    }

    @Test void concurrentPolicyChangeReturnsFixedRenderingFlags() throws Exception {
        when(policy.revision()).thenReturn("before-owner-change", "after-owner-change");
        mvc.perform(get("/api/ui-policy").header("Authorization", bearer("alice")))
                .andExpect(status().isOk()).andExpect(jsonPath("$.xssEnabled").value(false))
                .andExpect(jsonPath("$.supplyChainEnabled").value(false))
                .andExpect(jsonPath("$.revision").value("after-owner-change"));
    }

    @Test void contentBoundsAndMissingFieldsAreValidated() throws Exception {
        for (String path : new String[]{"/api/orders/ORD-A-100/notes", "/api/secure/orders/ORD-A-100/notes"}) {
            mvc.perform(put(path).header("Authorization", bearer("alice"))
                    .contentType(MediaType.APPLICATION_JSON).content("{}"))
                    .andExpect(status().isBadRequest());
            mvc.perform(put(path).header("Authorization", bearer("alice"))
                    .contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(Map.of("html", "x".repeat(8193)))))
                    .andExpect(status().isBadRequest());
        }
        mvc.perform(put("/api/vendor/widget").header("Authorization", bearer("alice"))
                .contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(Map.of("script", "x".repeat(16385)))))
                .andExpect(status().isBadRequest());
    }

    @Test void supplierTamperingIsAnExplicitFlaggedExerciseAndCannotChangeThePin() throws Exception {
        String marker = "document.body.dataset.northstarSupplyChain='seen';";
        String body = json.writeValueAsString(Map.of("script", marker));
        mvc.perform(get("/api/vendor/widget.js")).andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(content().string(SupplierWidget.TRUSTED_SCRIPT));
        mvc.perform(put("/api/vendor/widget").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isUnauthorized());
        mvc.perform(put("/api/vendor/widget").header("Authorization", bearer("alice"))
                .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isOk());
        mvc.perform(get("/api/vendor/widget.js")).andExpect(content().string(marker));
        mvc.perform(get("/api/secure/vendor/widget.js")).andExpect(content().string(SupplierWidget.TRUSTED_SCRIPT));
        mvc.perform(get("/api/ui-policy").header("Authorization", bearer("alice")))
                .andExpect(jsonPath("$.widgetIntegrity").value(SupplierWidget.INTEGRITY));
        when(policy.enabled("SC-01")).thenReturn(false);
        // Neither ordinary application users nor application administrators are owner publishers.
        for (String user : new String[]{"alice", "admin-a"}) {
            mvc.perform(put("/api/vendor/widget").header("Authorization", bearer(user))
                    .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isForbidden());
        }
        assertThat(SupplierWidget.INTEGRITY).isEqualTo("sha384-QCSo6c2cwb9ScxwSQfPKbs5MQw/5DE4QrDDcmAdDdOQG1DeU0bx0GxT0A/vQ9X4O");
        store.reset();
        mvc.perform(get("/api/vendor/widget.js")).andExpect(content().string(SupplierWidget.TRUSTED_SCRIPT));
        assertThat(store.orderNotes("ORD-A-100")).doesNotContain("onerror");
    }
}
