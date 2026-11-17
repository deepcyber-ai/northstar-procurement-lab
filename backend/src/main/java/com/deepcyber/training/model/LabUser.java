package com.deepcyber.training.model;

public record LabUser(
        String id,
        String displayName,
        String email,
        String tenantId,
        String organizationName,
        String jobTitle,
        LabRole role
) {
}
