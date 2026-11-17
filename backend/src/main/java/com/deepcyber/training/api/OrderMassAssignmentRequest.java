package com.deepcyber.training.api;

import java.math.BigDecimal;

public record OrderMassAssignmentRequest(
        String tenantId,
        String ownerId,
        String item,
        Integer quantity,
        BigDecimal unitPrice,
        String status
) {
}
