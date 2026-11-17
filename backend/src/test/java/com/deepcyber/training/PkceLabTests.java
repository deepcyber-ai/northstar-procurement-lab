package com.deepcyber.training;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties={"lab.training-mode=true"})
@AutoConfigureMockMvc
class PkceLabTests extends OAuthTestSupport {
    @Test void onlyMissingVerifierBypassesPkceInLabMode() throws Exception {
        mvc.perform(post("/auth/token").param("client_id","northstar-spa").param("grant_type","authorization_code")
                .param("code",code("alice")).param("redirect_uri","http://localhost:8080/callback"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.access_token").isString());
        mvc.perform(post("/auth/token").param("client_id","northstar-spa").param("grant_type","authorization_code")
                .param("code",code("alice")).param("redirect_uri","http://localhost:8080/callback").param("code_verifier","wrong"))
                .andExpect(status().is4xxClientError());
        mvc.perform(post("/auth/token").param("client_id","northstar-spa").param("grant_type","authorization_code")
                .param("code",code("alice")).param("redirect_uri","http://attacker.invalid/callback"))
                .andExpect(status().is4xxClientError());
    }
}
