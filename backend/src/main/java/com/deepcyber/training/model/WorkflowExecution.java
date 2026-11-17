package com.deepcyber.training.model;

import java.time.Instant;

public class WorkflowExecution {
    private final String id;
    private final String orderId;
    private final String tenantId;
    private final String requestedBy;
    private final String action;
    private String status;
    private final int executionNumber;
    private int callbackCount;
    private final Instant createdAt;

    public WorkflowExecution(String id, String orderId, String tenantId, String requestedBy, String action,
                             String status, int executionNumber, int callbackCount, Instant createdAt) {
        this.id = id;
        this.orderId = orderId;
        this.tenantId = tenantId;
        this.requestedBy = requestedBy;
        this.action = action;
        this.status = status;
        this.executionNumber = executionNumber;
        this.callbackCount = callbackCount;
        this.createdAt = createdAt;
    }

    public WorkflowExecution copy() {
        return new WorkflowExecution(id, orderId, tenantId, requestedBy, action, status,
                executionNumber, callbackCount, createdAt);
    }

    public String getId() { return id; }
    public String getOrderId() { return orderId; }
    public String getTenantId() { return tenantId; }
    public String getRequestedBy() { return requestedBy; }
    public String getAction() { return action; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public int getExecutionNumber() { return executionNumber; }
    public int getCallbackCount() { return callbackCount; }
    public void setCallbackCount(int callbackCount) { this.callbackCount = callbackCount; }
    public Instant getCreatedAt() { return createdAt; }
}
