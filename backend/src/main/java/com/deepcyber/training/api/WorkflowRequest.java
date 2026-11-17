package com.deepcyber.training.api;

import jakarta.validation.constraints.NotBlank;

public record WorkflowRequest(
        @NotBlank String orderId,
        @NotBlank String action
) {
}
