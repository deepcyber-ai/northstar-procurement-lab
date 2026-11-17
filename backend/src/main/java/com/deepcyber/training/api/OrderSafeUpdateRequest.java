package com.deepcyber.training.api;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;

public record OrderSafeUpdateRequest(
        @Size(min = 3, max = 80) String item,
        @Min(1) @Max(100) Integer quantity
) {
}
