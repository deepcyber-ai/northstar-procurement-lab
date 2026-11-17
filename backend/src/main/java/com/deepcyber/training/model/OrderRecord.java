package com.deepcyber.training.model;

import java.math.BigDecimal;

public class OrderRecord {
    private String id;
    private String tenantId;
    private String ownerId;
    private String item;
    private int quantity;
    private BigDecimal unitPrice;
    private String status;
    private int workflowStarts;
    private long version;

    public OrderRecord() {
    }

    public OrderRecord(String id, String tenantId, String ownerId, String item, int quantity,
                       BigDecimal unitPrice, String status, int workflowStarts, long version) {
        this.id = id;
        this.tenantId = tenantId;
        this.ownerId = ownerId;
        this.item = item;
        this.quantity = quantity;
        this.unitPrice = unitPrice;
        this.status = status;
        this.workflowStarts = workflowStarts;
        this.version = version;
    }

    public OrderRecord copy() {
        return new OrderRecord(id, tenantId, ownerId, item, quantity, unitPrice, status, workflowStarts, version);
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getTenantId() { return tenantId; }
    public void setTenantId(String tenantId) { this.tenantId = tenantId; }
    public String getOwnerId() { return ownerId; }
    public void setOwnerId(String ownerId) { this.ownerId = ownerId; }
    public String getItem() { return item; }
    public void setItem(String item) { this.item = item; }
    public int getQuantity() { return quantity; }
    public void setQuantity(int quantity) { this.quantity = quantity; }
    public BigDecimal getUnitPrice() { return unitPrice; }
    public void setUnitPrice(BigDecimal unitPrice) { this.unitPrice = unitPrice; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public int getWorkflowStarts() { return workflowStarts; }
    public void setWorkflowStarts(int workflowStarts) { this.workflowStarts = workflowStarts; }
    public long getVersion() { return version; }
    public void setVersion(long version) { this.version = version; }

    public BigDecimal getTotal() {
        return unitPrice.multiply(BigDecimal.valueOf(quantity));
    }
}
