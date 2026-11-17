package com.deepcyber.training.api;

import java.math.BigDecimal;

public record AdminOverview(
        String generatedFor,
        String scope,
        String trustedRoleSource,
        int userCount,
        int orderCount,
        int workflowCount,
        BigDecimal totalOrderValue,
        boolean trainingOnly
) {
}
