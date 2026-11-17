package com.deepcyber.training.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class HealthController {
    @GetMapping({"/health", "/api/health"})
    public Map<String, Object> health() {
        return Map.of(
                "status", "UP",
                "application", "deep-cyber-sample-backend",
                "trainingOnly", true,
                "warning", "DELIBERATELY VULNERABLE - NEVER DEPLOY TO PRODUCTION");
    }
}
