package com.deepcyber.training;

import com.deepcyber.training.store.LabStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties={"lab.training-mode=true", "lab.reset-token=test-management-token-at-least-32-characters"})
@AutoConfigureMockMvc
class DatabaseLabTests extends OAuthTestSupport {
    private static final String TOKEN = "test-management-token-at-least-32-characters";
    @Autowired MockMvc mvc;
    @Autowired LabStore store;
    @BeforeEach void seed() { store.reset(); }

    @Test void configExposureIsAllowlistedAndSafeRouteRequiresManagement() throws Exception {
        mvc.perform(get("/api/debug/database-config"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.engine").value("SQLite"))
                .andExpect(jsonPath("$.resetToken").doesNotExist()).andExpect(jsonPath("$.password").doesNotExist());
        mvc.perform(get("/api/secure/debug/database-config")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/secure/debug/database-config").header("X-Lab-Reset-Token", TOKEN))
                .andExpect(status().isOk());
    }
    @Test void searchInjectionReadsAcrossTenantsButSafeRouteDoesNot() throws Exception {
        mvc.perform(get("/api/orders/search").param("q","").header("Authorization",bearer("alice")))
                .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(2));
        mvc.perform(get("/api/orders/search").param("q","' OR 1=1 -- ").header("Authorization",bearer("alice")))
                .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(4));
        mvc.perform(get("/api/secure/orders/search").param("q","' OR 1=1 -- ").header("Authorization",bearer("alice")))
                .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(0));
        mvc.perform(get("/api/orders/search")).andExpect(status().isUnauthorized());
    }
    @Test void updateInjectionChangesOtherTenantsAndResetRestoresEverything() throws Exception {
        mvc.perform(post("/api/orders/submit").header("Authorization",bearer("alice"))
                .contentType(MediaType.APPLICATION_JSON).content("{\"orderId\":\"ORD-B-100\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.updated").value(0));
        mvc.perform(post("/api/orders/submit").header("Authorization",bearer("alice"))
                .contentType(MediaType.APPLICATION_JSON).content("{\"orderId\":\"ORD-A-100' OR 1=1 -- \"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.updated").value(4));
        assertThat(store.findOrder("ORD-B-100").orElseThrow().getStatus()).isEqualTo("PENDING_APPROVAL");
        var alice = store.findUser("alice").orElseThrow();
        store.createIdempotentWorkflow(alice,"ORD-A-100","SUBMIT_FOR_APPROVAL","reset-test");
        mvc.perform(post("/api/lab/reset").header("X-Lab-Reset-Token",TOKEN)
                .header("X-Lab-Confirm-Reset","RESET-SYNTHETIC-DATA"))
                .andExpect(status().isOk());
        assertThat(store.findOrder("ORD-B-100").orElseThrow().getStatus()).isEqualTo("DRAFT");
        assertThat(store.listWorkflows()).isEmpty();
        assertThat(store.createIdempotentWorkflow(alice,"ORD-A-100","SUBMIT_FOR_APPROVAL","reset-test").replayed()).isFalse();
    }
    @Test void safeUpdateUsesLiteralIdsAndChecksOwnership() throws Exception {
        mvc.perform(post("/api/secure/orders/submit").header("Authorization",bearer("alice"))
                .contentType(MediaType.APPLICATION_JSON).content("{\"orderId\":\"ORD-A-100' OR 1=1 -- \"}"))
                .andExpect(status().isNotFound());
        mvc.perform(post("/api/secure/orders/submit").header("Authorization",bearer("alice"))
                .contentType(MediaType.APPLICATION_JSON).content("{\"orderId\":\"ORD-B-100\"}"))
                .andExpect(status().isForbidden());
        mvc.perform(post("/api/secure/orders/submit").header("Authorization",bearer("alice"))
                .contentType(MediaType.APPLICATION_JSON).content("{\"orderId\":\"ORD-A-100\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.updated").value(1));
        assertThat(store.findOrder("ORD-B-100").orElseThrow().getStatus()).isEqualTo("DRAFT");
    }
    @Test void resetRequiresSeparateSecretAndConfirmation() throws Exception {
        mvc.perform(post("/api/lab/reset").header("Authorization",bearer("admin-a")))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/lab/reset").header("X-Lab-Reset-Token","wrong"))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/lab/reset").header("X-Lab-Reset-Token",TOKEN))
                .andExpect(status().isBadRequest());
    }
}
