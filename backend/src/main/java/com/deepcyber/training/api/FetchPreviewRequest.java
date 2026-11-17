package com.deepcyber.training.api;

import jakarta.validation.constraints.NotBlank;

public record FetchPreviewRequest(@NotBlank String url) {
}
