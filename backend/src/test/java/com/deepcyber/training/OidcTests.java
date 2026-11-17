package com.deepcyber.training;

import com.deepcyber.training.auth.*;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.*;
import java.time.Instant;
import java.util.List;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class OidcTests extends OAuthTestSupport {
    @Autowired @Qualifier("apiDecoder") JwtDecoder decoder;
    @Autowired IdentityDatabase db;
    @Autowired RegisteredClientRepository clients;
    @Autowired LabAuthorizations grants;
    @Autowired JwtEncoder encoder;

    @Test void disablingTrainingAlsoDisablesVulnerableApiAndManagementRoutes() throws Exception {
        mvc.perform(get("/api/orders/ORD-B-100").header("Authorization",bearer("alice"))).andExpect(status().isForbidden());
        mvc.perform(get("/api/debug/database-config")).andExpect(status().isNotFound());
        mvc.perform(post("/api/lab/reset")).andExpect(status().isNotFound());
    }

    @Test void signedTokensStillRequireAudienceAndFreshExpiry() throws Exception {
        var real=decoder.decode(tokens("alice").get("access_token").asText());
        for (boolean expired:new boolean[]{true,false}) {
            var claims=JwtClaimsSet.builder().issuer("http://localhost:8080").subject("alice")
                    .audience(List.of(expired?"northstar-api":"another-api"))
                    .issuedAt(Instant.now().minusSeconds(300))
                    .expiresAt(expired?Instant.now().minusSeconds(120):Instant.now().plusSeconds(3600))
                    .claim("scope",List.of("northstar.api")).claim("token_use","access")
                    .claim("sid",real.getClaimAsString("sid")).build();
            String token=encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
            mvc.perform(get("/api/orders").header("Authorization","Bearer "+token)).andExpect(status().isUnauthorized());
        }
    }

    @Test void discoveryAndTokensAreRealAndIdTokenCannotAuthorizeApi() throws Exception {
        mvc.perform(get("/.well-known/openid-configuration")).andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("http://localhost:8080"))
                .andExpect(jsonPath("$.token_endpoint").value("http://localhost:8080/auth/token"));
        var t=tokens("alice");
        assertThat(t.get("refresh_token").asText()).hasSizeGreaterThan(40);
        var jwt=decoder.decode(t.get("access_token").asText());
        assertThat(jwt.getExpiresAt().getEpochSecond()-jwt.getIssuedAt().getEpochSecond()).isEqualTo(86400);
        assertThat(jwt.getAudience()).containsExactly("northstar-api");
        mvc.perform(get("/api/orders").header("Authorization","Bearer "+t.get("id_token").asText())).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/orders").header("Authorization","Bearer training-token-alice")).andExpect(status().isUnauthorized());
        String access=t.get("access_token").asText();
        int signature=access.lastIndexOf('.')+1;
        String tampered=access.substring(0,signature)+(access.charAt(signature)=='A'?"B":"A")+access.substring(signature+1);
        mvc.perform(get("/api/orders").header("Authorization","Bearer "+tampered)).andExpect(status().isUnauthorized());
    }
    @Test void strictPkceRejectsAbsentWrongAndEmptyVerifier() throws Exception {
        for(String verifier:new String[]{"ABSENT","","wrong-verifier"}) {
            var request=post("/auth/token").param("grant_type","authorization_code").param("client_id","northstar-spa")
                    .param("redirect_uri","http://localhost:8080/callback").param("code",code("alice"));
            if(!verifier.equals("ABSENT"))request.param("code_verifier",verifier);
            mvc.perform(request).andExpect(status().is4xxClientError());
        }
    }
    @Test void codeCannotBeReusedOrRedeemedAtAnotherRedirect() throws Exception {
        String code=code("alice");
        var request=post("/auth/token").param("grant_type","authorization_code").param("client_id","northstar-spa")
                .param("redirect_uri","http://localhost:8080/callback").param("code",code).param("code_verifier",VERIFIER);
        mvc.perform(request).andExpect(status().isOk());
        mvc.perform(request).andExpect(status().is4xxClientError());
        mvc.perform(post("/auth/token").param("grant_type","authorization_code").param("client_id","northstar-spa")
                .param("redirect_uri","http://localhost:8080/other").param("code",code("alice")).param("code_verifier",VERIFIER))
                .andExpect(status().is4xxClientError());
    }
    @Test void refreshRotatesPersistsAndReplayRevokesTheFamily() throws Exception {
        var first=tokens("alice");
        String raw=first.get("refresh_token").asText();
        var reopened=new LabAuthorizations(db,clients);
        var original=reopened.findByToken(raw,OAuth2TokenType.REFRESH_TOKEN);
        assertThat(original).isNotNull();
        String stored=db.jdbc.queryForObject("SELECT refresh_token_value FROM oauth2_authorization WHERE id=?",String.class,original.getId());
        assertThat(stored).startsWith("sha256:").doesNotContain(raw);
        JsonNode next=mapper.readTree(mvc.perform(post("/auth/token")
                .param("client_id","northstar-spa").param("grant_type","refresh_token").param("refresh_token",raw))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertThat(next.get("refresh_token").asText()).isNotEqualTo(raw);
        var rotated=grants.findByToken(next.get("refresh_token").asText(),OAuth2TokenType.REFRESH_TOKEN);
        assertThat(rotated.getRefreshToken().getToken().getExpiresAt()).isEqualTo(original.getRefreshToken().getToken().getExpiresAt());
        mvc.perform(get("/api/orders").header("Authorization","Bearer "+next.get("access_token").asText())).andExpect(status().isOk());
        mvc.perform(post("/auth/token").param("client_id","northstar-spa").param("grant_type","refresh_token").param("refresh_token",raw))
                .andExpect(status().is4xxClientError());
        mvc.perform(get("/api/orders").header("Authorization","Bearer "+next.get("access_token").asText())).andExpect(status().isUnauthorized());
        mvc.perform(post("/auth/token").param("client_id","northstar-spa").param("grant_type","refresh_token").param("refresh_token",next.get("refresh_token").asText()))
                .andExpect(status().is4xxClientError());
    }
    @Test void logoutRevokesAccessAndRefreshWithoutResettingBusinessData() throws Exception {
        var t=tokens("alice");
        mvc.perform(post("/auth/session/logout").header("Authorization","Bearer "+t.get("access_token").asText())).andExpect(status().isOk());
        mvc.perform(get("/api/orders").header("Authorization","Bearer "+t.get("access_token").asText())).andExpect(status().isUnauthorized());
        mvc.perform(post("/auth/token").param("client_id","northstar-spa").param("grant_type","refresh_token").param("refresh_token",t.get("refresh_token").asText()))
                .andExpect(status().is4xxClientError());
    }
    @Test void loginPageDoesNotAdvertiseDemoCredentials() throws Exception {
        for (String path : new String[]{"/auth/login", "/auth/login?error"}) {
            var request=get("/auth/login");
            // MockMvc does not populate getParameter for a bare ?error URI;
            // explicitly model the servlet's empty-valued error parameter.
            if (path.endsWith("?error")) request.param("error", "");
            String page=mvc.perform(request).andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString();
            assertThat(page).contains("<title>Northstar Login</title>", "<h1>Northstar Login</h1>", "name=\"_csrf\"")
                    .containsPattern("<form\\b(?=[^>]*\\bmethod=\"post\")(?=[^>]*\\baction=\"/auth/login\")[^>]*>")
                    .containsPattern("<label\\b[^>]*\\bfor=\"email\"[^>]*>Work email</label>")
                    .containsPattern("<input\\b(?=[^>]*\\bid=\"email\")(?=[^>]*\\bname=\"username\")(?=[^>]*\\btype=\"email\")(?=[^>]*\\bautocomplete=\"username\")[^>]*>")
                    .containsPattern("<label\\b[^>]*\\bfor=\"password\"[^>]*>Password</label>")
                    .containsPattern("<input\\b(?=[^>]*\\bid=\"password\")(?=[^>]*\\bname=\"password\")(?=[^>]*\\btype=\"password\")(?=[^>]*\\bautocomplete=\"current-password\")[^>]*>")
                    .containsPattern("<button\\b[^>]*\\btype=\"submit\"[^>]*>Sign in</button>")
                    .doesNotContain("Synthetic lab accounts only", "Demo password", "Welcome123!",
                            "alice.avery@aster-row.test", "bob.baker@beacon-works.test", "ada.morgan@aster-row.test");
            if (path.endsWith("?error")) {
                assertThat(page).contains("Sign-in failed. Check your credentials.");
            } else {
                assertThat(page).doesNotContain("Sign-in failed. Check your credentials.");
            }
        }
    }
    @Test void formLoginRequiresCsrfAndChecksPassword() throws Exception {
        mvc.perform(post("/auth/login").param("username","alice.avery@aster-row.test").param("password","Welcome123!"))
                .andExpect(status().isForbidden());
        mvc.perform(post("/auth/login").with(csrf()).param("username","alice.avery@aster-row.test").param("password","wrong"))
                .andExpect(redirectedUrl("/auth/login?error"));
        mvc.perform(post("/auth/login").with(csrf()).param("username","alice.avery@aster-row.test").param("password","Welcome123!"))
                .andExpect(status().is3xxRedirection());
        assertThat(db.jdbc.queryForObject("SELECT password_hash FROM identity_users WHERE id='alice'",String.class)).startsWith("$2a$");
    }
}
