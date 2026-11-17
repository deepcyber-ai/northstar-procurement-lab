package com.deepcyber.training;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties={"lab.training-mode=true", "lab.vulnerabilities-default=fixed", "lab.reset-token="})
@AutoConfigureMockMvc
class ManagementDisabledTests {
    @Autowired MockMvc mvc;
    @Test void missingConfigurationDoesNotAcceptAnySuppliedSecret() throws Exception {
        mvc.perform(post("/api/lab/reset")
                .header("X-Lab-Reset-Token","an-arbitrary-token-at-least-32-characters")
                .header("X-Lab-Confirm-Reset","RESET-SYNTHETIC-DATA"))
                .andExpect(status().isNotFound());
    }
    @Test void secureCallbackNeverFallsBackToTheOldPublishedLabConstant() throws Exception {
        for (String path : new String[]{"/api/secure/workflows/WF-0001/callback", "/api/workflows/WF-0001/callback"}) {
            mvc.perform(post(path)
                    .header("X-Workflow-Callback-Token","training-callback-token-v1")
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .content("{\"status\":\"COMPLETED\"}"))
                    .andExpect(status().isNotFound())
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.code").value("CALLBACK_DISABLED"));
        }
    }
}
