package com.deepcyber.training;

import com.deepcyber.training.store.LabStore;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties={"lab.training-mode=true", "lab.callback-token=test-callback-token-at-least-32-characters"})
@AutoConfigureMockMvc
class TrainingLabApiTests extends OAuthTestSupport {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired LabStore store;

    @BeforeEach
    void resetSeedData() {
        store.reset();
    }

    @Test
    void defaultVulnerableLabExposesMetadataButResetRemainsProtected() throws Exception {
        mvc.perform(get("/api/debug/database-config")).andExpect(status().isOk());
        mvc.perform(post("/api/lab/reset")).andExpect(status().isNotFound());
    }

    @Test
    void healthEndpointCarriesAnUnmissableTrainingBanner() throws Exception {
        mvc.perform(get("/api/health"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Training-Lab", "DELIBERATELY-VULNERABLE-DO-NOT-DEPLOY"))
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.trainingOnly").value(true))
                .andExpect(jsonPath("$.warning").value("DELIBERATELY VULNERABLE - NEVER DEPLOY TO PRODUCTION"));
    }

    @Test
    void userLoginMatchesTheFrontendContract() throws Exception {
        mvc.perform(get("/api/auth/me").header("Authorization",bearer("alice")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value("alice"))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    void invalidPasswordIsRejected() throws Exception {
        mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"alice.avery@aster-row.test\",\"password\":\"wrong\"}"))
                .andExpect(status().isGone());
    }

    @Test
    void vulnerableOrderDetailHasCrossTenantIdorButSecureRouteBlocksIt() throws Exception {
        mvc.perform(get("/api/orders/ORD-B-100").header("Authorization", bearer("alice")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenantId").value("tenant-b"))
                .andExpect(jsonPath("$.ownerId").value("bob"));

        mvc.perform(get("/api/secure/orders/ORD-B-100").header("Authorization", bearer("alice")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ACCESS_DENIED"));
    }

    @Test
    void vulnerableUpdateMassAssignsProtectedFields() throws Exception {
        mvc.perform(patch("/api/orders/ORD-A-100")
                        .header("Authorization", bearer("alice"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "tenantId":"tenant-b",
                                  "ownerId":"bob",
                                  "unitPrice":0.01,
                                  "status":"APPROVED"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenantId").value("tenant-b"))
                .andExpect(jsonPath("$.ownerId").value("bob"))
                .andExpect(jsonPath("$.unitPrice").value(0.01))
                .andExpect(jsonPath("$.status").value("APPROVED"));
    }

    @Test
    void secureUpdateRejectsProtectedFieldsAndLeavesTheOrderUnchanged() throws Exception {
        mvc.perform(patch("/api/secure/orders/ORD-A-100")
                        .header("Authorization", bearer("alice"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"APPROVED\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));

        assertThat(store.findOrder("ORD-A-100").orElseThrow().getStatus()).isEqualTo("DRAFT");
    }

    @Test
    void vulnerableAdminTrustsGatewayRoleHeaderWhileSecureAdminUsesSeededIdentity() throws Exception {
        mvc.perform(get("/api/admin/overview")
                        .header("Authorization", bearer("alice"))
                        .header("X-Authenticated-Role", "ADMIN"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scope").value("all-tenants"))
                .andExpect(jsonPath("$.orderCount").value(4));

        mvc.perform(get("/api/secure/admin/overview")
                        .header("Authorization", bearer("alice"))
                        .header("X-Training-User", "admin-a")
                        .header("X-Authenticated-Role", "ADMIN"))
                .andExpect(status().isForbidden());

        mvc.perform(get("/api/secure/admin/overview")
                        .header("Authorization", bearer("admin-a"))
                        .header("X-Authenticated-Role", "USER"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scope").value("tenant:tenant-a"))
                .andExpect(jsonPath("$.orderCount").value(2));
    }

    @Test
    void callerSuppliedUserHeaderCannotReplaceBearerIdentity() throws Exception {
        mvc.perform(get("/api/secure/admin/overview")
                        .header("X-Training-User", "admin-a")
                        .header("X-Authenticated-Role", "ADMIN"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("AUTH_REQUIRED"));
    }

    @Test
    void ssrfExerciseIsSimulatedLocallyAndSecureRouteUsesAnAllowlist() throws Exception {
        mvc.perform(post("/api/tools/fetch-preview")
                        .header("Authorization", bearer("alice"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"url\":\"http://169.254.169.254/latest/meta-data/iam\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.networkAccessPerformed").value(false))
                .andExpect(jsonPath("$.body").value(org.hamcrest.Matchers.containsString("FAKE-TRAINING-TOKEN")));

        mvc.perform(post("/api/secure/tools/fetch-preview")
                        .header("Authorization", bearer("alice"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"url\":\"http://169.254.169.254/latest/meta-data/iam\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("URL_NOT_ALLOWLISTED"));

        mvc.perform(post("/api/secure/tools/fetch-preview")
                        .header("Authorization", bearer("alice"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"url\":\"https://public.example.test/assets/manual.txt\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.networkAccessPerformed").value(false));
    }

    @Test
    void vulnerableWorkflowCanBeReplayedWhileSecureWorkflowIsIdempotent() throws Exception {
        String request = "{\"orderId\":\"ORD-A-100\",\"action\":\"SUBMIT_FOR_APPROVAL\"}";

        String firstUnsafeId = workflowId(mvc.perform(post("/api/workflows")
                        .header("Authorization", bearer("alice"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isCreated()).andReturn());
        String secondUnsafeId = workflowId(mvc.perform(post("/api/workflows")
                        .header("Authorization", bearer("alice"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isCreated()).andReturn());

        assertThat(firstUnsafeId).isNotEqualTo(secondUnsafeId);
        assertThat(store.findOrder("ORD-A-100").orElseThrow().getWorkflowStarts()).isEqualTo(2);

        store.reset();
        String firstSafeId = workflowId(mvc.perform(post("/api/secure/workflows")
                        .header("Authorization", bearer("alice"))
                        .header("Idempotency-Key", "alice-order-100-submit")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isCreated())
                .andExpect(header().string("X-Idempotent-Replay", "false"))
                .andReturn());
        String replaySafeId = workflowId(mvc.perform(post("/api/secure/workflows")
                        .header("Authorization", bearer("alice"))
                        .header("Idempotency-Key", "alice-order-100-submit")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Idempotent-Replay", "true"))
                .andReturn());

        assertThat(replaySafeId).isEqualTo(firstSafeId);
        assertThat(store.findOrder("ORD-A-100").orElseThrow().getWorkflowStarts()).isEqualTo(1);
    }

    @Test
    void secureWorkflowStatusChecksTenantAndSecureCallbackRejectsReplay() throws Exception {
        String request = "{\"orderId\":\"ORD-A-100\",\"action\":\"SUBMIT_FOR_APPROVAL\"}";
        String workflowId = workflowId(mvc.perform(post("/api/secure/workflows")
                        .header("Authorization", bearer("alice"))
                        .header("Idempotency-Key", "callback-test-key")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isCreated()).andReturn());

        mvc.perform(get("/api/secure/workflows/" + workflowId).header("Authorization", bearer("bob")))
                .andExpect(status().isForbidden());

        mvc.perform(post("/api/secure/workflows/" + workflowId + "/callback")
                        .header("X-Workflow-Callback-Token", "test-callback-token-at-least-32-characters")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"COMPLETED\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.callbackCount").value(1));

        mvc.perform(post("/api/secure/workflows/" + workflowId + "/callback")
                        .header("X-Workflow-Callback-Token", "test-callback-token-at-least-32-characters")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"COMPLETED\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("CALLBACK_ALREADY_HANDLED"));
    }

    @Test
    void corsAllowsLocalAngularDevelopmentOrigin() throws Exception {
        mvc.perform(options("/api/orders")
                        .header("Origin", "http://localhost:4200")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:4200"));
    }

    private String workflowId(MvcResult result) throws Exception {
        JsonNode node = objectMapper.readTree(result.getResponse().getContentAsString());
        return node.get("id").asText();
    }
}
