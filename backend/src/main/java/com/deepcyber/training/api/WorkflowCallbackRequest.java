package com.deepcyber.training.api;

import jakarta.validation.constraints.NotBlank;

public record WorkflowCallbackRequest(@NotBlank String status) {
}
