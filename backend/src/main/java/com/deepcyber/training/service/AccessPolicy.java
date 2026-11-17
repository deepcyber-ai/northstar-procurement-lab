package com.deepcyber.training.service;

import com.deepcyber.training.model.LabRole;
import com.deepcyber.training.model.LabUser;
import com.deepcyber.training.model.OrderRecord;
import org.springframework.stereotype.Component;

@Component
public class AccessPolicy {
    public boolean canReadOrder(LabUser user, OrderRecord order) {
        return user.tenantId().equals(order.getTenantId())
                && (user.id().equals(order.getOwnerId()) || user.role() == LabRole.ADMIN);
    }

    public boolean canEditOrder(LabUser user, OrderRecord order) {
        return user.tenantId().equals(order.getTenantId()) && user.id().equals(order.getOwnerId());
    }
}
