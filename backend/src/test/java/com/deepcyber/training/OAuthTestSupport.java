package com.deepcyber.training;

import com.fasterxml.jackson.databind.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.util.UriComponentsBuilder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

abstract class OAuthTestSupport {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    static final String VERIFIER = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
    String code(String subject) throws Exception {
        String challenge=Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(VERIFIER.getBytes(StandardCharsets.US_ASCII)));
        String location=mvc.perform(get("/auth/authorize").with(user(subject))
                .queryParam("client_id","northstar-spa").queryParam("redirect_uri","http://localhost:8080/callback")
                .queryParam("response_type","code").queryParam("scope","openid profile offline_access northstar.api")
                .queryParam("state","test-state").queryParam("nonce","test-nonce")
                .queryParam("code_challenge",challenge).queryParam("code_challenge_method","S256"))
                .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
        String code=UriComponentsBuilder.fromUriString(location).build().getQueryParams().getFirst("code");
        if(code==null) throw new AssertionError("No authorization code: "+location);
        return code;
    }
    JsonNode tokens(String subject) throws Exception {
        return mapper.readTree(mvc.perform(post("/auth/token")
                .param("grant_type","authorization_code").param("client_id","northstar-spa")
                .param("redirect_uri","http://localhost:8080/callback")
                .param("code",code(subject)).param("code_verifier",VERIFIER))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
    }
    String bearer(String subject) throws Exception { return "Bearer "+tokens(subject).get("access_token").asText(); }
}
