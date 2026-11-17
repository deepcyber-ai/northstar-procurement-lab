package com.deepcyber.training.api;

import com.deepcyber.training.model.LabUser;

public record LoginResponse(String token, LabUser user, boolean trainingOnly) {
}
