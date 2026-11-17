package com.deepcyber.training.service;

import com.deepcyber.training.api.LabApiException;
import com.deepcyber.training.model.LabUser;
import com.deepcyber.training.store.LabStore;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.jwt.*;

@Service
public class IdentityService {
    private final LabStore store;
    private final JwtDecoder decoder;

    public IdentityService(LabStore store, @Qualifier("apiDecoder") JwtDecoder decoder) {
        this.store = store;
        this.decoder = decoder;
    }

    public LabUser authenticate(HttpServletRequest request) {
        return store.findUser(accessToken(request).getSubject())
                .orElseThrow(() -> new LabApiException(HttpStatus.UNAUTHORIZED, "UNKNOWN_PERSONA",
                        "The supplied training persona is not recognised"));
    }

    public Jwt accessToken(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.startsWith("Bearer ")) {
            try { return decoder.decode(authorization.substring(7)); }
            catch (JwtException ignored) { /* Return one non-sensitive authentication error. */ }
        }
        throw new LabApiException(HttpStatus.UNAUTHORIZED, "AUTH_REQUIRED", "Sign in to Northstar and send an access token");
    }
}
