package com.deepcyber.training.controller;

import com.deepcyber.training.api.LabApiException;
import com.deepcyber.training.model.LabUser;
import com.deepcyber.training.service.IdentityService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final IdentityService identityService;

    public AuthController(IdentityService identityService) {
        this.identityService = identityService;
    }

    @PostMapping("/login")
    public void login() {
        throw new LabApiException(HttpStatus.GONE, "OAUTH_LOGIN_REQUIRED", "Use the browser OAuth sign-in flow");
    }

    @GetMapping("/me") public LabUser me(HttpServletRequest request) { return identityService.authenticate(request); }

}
