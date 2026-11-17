package com.deepcyber.training.config;

import com.deepcyber.training.service.VulnerabilityPolicy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;
import java.util.List;

@Configuration
public class WebConfig {
    @Bean
    FilterRegistrationBean<CorsFilter> labCorsFilter(VulnerabilityPolicy vulnerabilities,
            @Value("${lab.allowed-origin-patterns:http://localhost:*}") String configuredPatterns) {
        List<String> allowed = Arrays.stream(configuredPatterns.split(",")).map(String::trim)
                .filter(pattern -> !pattern.isBlank()).toList();
        CorsFilter filter = new CorsFilter(request -> {
            String path = request.getRequestURI();
            if (!path.startsWith("/api/")) return null;
            boolean unsafe = !path.equals("/api/secure") && !path.startsWith("/api/secure/")
                    && vulnerabilities.enabled("GW-03");
            CorsConfiguration config = new CorsConfiguration();
            config.setAllowedOriginPatterns(unsafe ? List.of("*") : allowed);
            config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "OPTIONS"));
            config.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Training-Lab", "X-Training-User",
                    "X-Training-Tenant", "X-Training-Role", "X-Authenticated-Role", "Idempotency-Key",
                    "X-Workflow-Callback-Token"));
            config.setExposedHeaders(List.of("X-Training-Lab", "X-Idempotent-Replay"));
            config.setAllowCredentials(unsafe);
            // Re-evaluate after a runtime switch instead of caching an unsafe preflight policy.
            config.setMaxAge(0L);
            return config;
        });
        var bean = new FilterRegistrationBean<>(filter);
        bean.setOrder(-190);
        return bean;
    }
}
