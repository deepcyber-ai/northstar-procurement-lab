package com.deepcyber.training.auth;

import com.deepcyber.training.service.VulnerabilityPolicy;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;
import java.util.HashMap;

/** Explicit lab extension: public refresh grants, and optionally a missing-verifier bypass. */
public class LabPublicClientProvider implements AuthenticationProvider {
    private final RegisteredClientRepository clients;
    private final PublicClientAuthenticationProvider strict;
    private final VulnerabilityPolicy vulnerabilities;
    public LabPublicClientProvider(RegisteredClientRepository clients, LabAuthorizations grants, VulnerabilityPolicy vulnerabilities) {
        this.clients=clients; this.strict=new PublicClientAuthenticationProvider(clients,grants); this.vulnerabilities=vulnerabilities;
    }
    public static AuthenticationConverter converter() {
        return request -> {
            if (!"POST".equals(request.getMethod()) || !"/auth/token".equals(request.getRequestURI())) return null;
            var parameters = new HashMap<String,Object>();
            request.getParameterMap().forEach((k,v) -> {
                if (v.length != 1) throw new OAuth2AuthenticationException("invalid_request");
                parameters.put(k,v[0]);
            });
            String id=request.getParameter("client_id");
            if (id == null || request.getHeader("Authorization") != null || parameters.containsKey("client_secret"))
                throw new OAuth2AuthenticationException("invalid_client");
            return new OAuth2ClientAuthenticationToken(id,ClientAuthenticationMethod.NONE,null,parameters);
        };
    }
    @Override public Authentication authenticate(Authentication input) {
        var token=(OAuth2ClientAuthenticationToken)input;
        if (!ClientAuthenticationMethod.NONE.equals(token.getClientAuthenticationMethod())) return null;
        var client=clients.findByClientId(token.getPrincipal().toString());
        if (client == null || !client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE))
            throw new OAuth2AuthenticationException("invalid_client");
        var p=token.getAdditionalParameters();
        boolean refresh="refresh_token".equals(p.get("grant_type"));
        // DELIBERATE PKCE FLAW: only an ABSENT verifier bypasses the standard check.
        boolean missingBypass=vulnerabilities.enabled("AUTH-01") && "authorization_code".equals(p.get("grant_type")) && !p.containsKey("code_verifier");
        if (refresh || missingBypass) return new OAuth2ClientAuthenticationToken(client,ClientAuthenticationMethod.NONE,null);
        return strict.authenticate(input);
    }
    @Override public boolean supports(Class<?> type) { return OAuth2ClientAuthenticationToken.class.isAssignableFrom(type); }
}
