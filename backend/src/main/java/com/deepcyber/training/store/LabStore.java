package com.deepcyber.training.store;

import com.deepcyber.training.api.LabApiException;
import com.deepcyber.training.model.*;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import java.math.BigDecimal;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

/** SQLite-backed storage. Synchronisation makes reset exclusive in this single-instance lab. */
@Component
public class LabStore {
    private final LabDatabase db;
    public LabStore(LabDatabase db) {
        this.db = db;
        if (db.query("SELECT value FROM metadata WHERE key='seed_version'", r -> r.getInt(1)).isEmpty()) reset();
    }
    public synchronized void reset() {
        db.transaction(() -> {
            for (String table : List.of("order_notes", "vendor_widget", "idempotency", "workflows", "orders", "users", "metadata"))
                db.update("DELETE FROM " + table);
            addUser("alice", "Alice Avery", "alice.avery@aster-row.test", "tenant-a", "Aster & Row", "Procurement Analyst", "USER");
            addUser("alex", "Alex Archer", "alex.archer@aster-row.test", "tenant-a", "Aster & Row", "Category Manager", "USER");
            addUser("admin-a", "Ada Morgan", "ada.morgan@aster-row.test", "tenant-a", "Aster & Row", "Procurement Administrator", "ADMIN");
            addUser("bob", "Bob Baker", "bob.baker@beacon-works.test", "tenant-b", "Beacon Works", "Buyer", "USER");
            addUser("admin-b", "Ben Carter", "ben.carter@beacon-works.test", "tenant-b", "Beacon Works", "Operations Administrator", "ADMIN");
            addOrder("ORD-A-100", "tenant-a", "alice", "Laptop stand", 1, "49.90", "DRAFT");
            addOrder("ORD-A-200", "tenant-a", "alex", "4K monitor", 2, "239.00", "PENDING_APPROVAL");
            addOrder("ORD-B-100", "tenant-b", "bob", "Security key", 5, "35.00", "DRAFT");
            addOrder("ORD-B-200", "tenant-b", "admin-b", "Backup appliance", 1, "899.00", "APPROVED");
            db.update("INSERT INTO metadata VALUES ('seed_version',1),('workflow_sequence',0)");
            return null;
        });
    }
    private void addUser(String id, String name, String email, String tenant, String organization, String title, String role) {
        // Authentication credentials live only in the separate identity database.
        db.update("INSERT INTO users VALUES (?,?,?,?,?,?,?)", id, name, email, tenant, organization, title, role);
    }
    private void addOrder(String id, String tenant, String owner, String item, int quantity, String price, String status) {
        db.update("INSERT INTO orders VALUES (?,?,?,?,?,?,?,0,1)", id, tenant, owner, item, quantity, price, status);
    }
    private LabUser user(ResultSet r) throws SQLException {
        return new LabUser(r.getString("id"), r.getString("name"), r.getString("email"), r.getString("tenant"),
                r.getString("organization"), r.getString("title"), LabRole.valueOf(r.getString("role")));
    }
    private OrderRecord order(ResultSet r) throws SQLException {
        return new OrderRecord(r.getString("id"), r.getString("tenant_id"), r.getString("owner_id"), r.getString("item"),
                r.getInt("quantity"), new BigDecimal(r.getString("unit_price")), r.getString("status"),
                r.getInt("workflow_starts"), r.getLong("version"));
    }
    private WorkflowExecution workflow(ResultSet r) throws SQLException {
        return new WorkflowExecution(r.getString("id"), r.getString("order_id"), r.getString("tenant_id"),
                r.getString("requested_by"), r.getString("action"), r.getString("status"), r.getInt("execution_number"),
                r.getInt("callback_count"), Instant.parse(r.getString("created_at")));
    }
    public synchronized Optional<LabUser> findUser(String id) {
        return db.query("SELECT * FROM users WHERE id=?", this::user, id).stream().findFirst();
    }
    public synchronized List<LabUser> listUsers() { return db.query("SELECT * FROM users ORDER BY id", this::user); }
    public synchronized Optional<OrderRecord> findOrder(String id) {
        return db.query("SELECT * FROM orders WHERE id=?", this::order, id).stream().findFirst();
    }
    public synchronized List<OrderRecord> listOrders() { return db.query("SELECT * FROM orders ORDER BY id", this::order); }
    public synchronized String orderNotes(String orderId) {
        requireOrder(orderId);
        return db.query("SELECT html FROM order_notes WHERE order_id=?", r -> r.getString(1), orderId)
                .stream().findFirst().orElse("<p>Please confirm delivery arrangements with the requester.</p>");
    }
    public synchronized void saveOrderNotes(String orderId, String html) {
        requireOrder(orderId);
        db.update("INSERT INTO order_notes(order_id,html) VALUES (?,?) ON CONFLICT(order_id) DO UPDATE SET html=excluded.html", orderId, html);
    }
    public synchronized String vendorWidget(String trustedDefault) {
        return db.query("SELECT script FROM vendor_widget WHERE id=1", r -> r.getString(1))
                .stream().findFirst().orElse(trustedDefault);
    }
    public synchronized void saveVendorWidget(String script) {
        db.update("INSERT INTO vendor_widget(id,script) VALUES (1,?) ON CONFLICT(id) DO UPDATE SET script=excluded.script", script);
    }
    public synchronized OrderRecord updateOrder(String id, Consumer<OrderRecord> update) {
        return db.transaction(() -> {
            OrderRecord order = requireOrder(id);
            update.accept(order);
            db.update("UPDATE orders SET tenant_id=?,owner_id=?,item=?,quantity=?,unit_price=?,status=?,workflow_starts=?,version=version+1 WHERE id=?",
                    order.getTenantId(), order.getOwnerId(), order.getItem(), order.getQuantity(), order.getUnitPrice().toPlainString(),
                    order.getStatus(), order.getWorkflowStarts(), id);
            return requireOrder(id);
        });
    }
    public synchronized WorkflowExecution createWorkflow(LabUser user, String orderId, String action) {
        return db.transaction(() -> {
            OrderRecord order = requireOrder(orderId);
            db.update("UPDATE metadata SET value=value+1 WHERE key='workflow_sequence'");
            int sequence = db.query("SELECT value FROM metadata WHERE key='workflow_sequence'", r -> r.getInt(1)).getFirst();
            String id = "WF-%04d".formatted(sequence);
            db.update("INSERT INTO workflows VALUES (?,?,?,?,?,'RUNNING',?,0,?)", id, orderId, order.getTenantId(), user.id(), action, sequence, Instant.now().toString());
            db.update("UPDATE orders SET workflow_starts=workflow_starts+1,version=version+1 WHERE id=?", orderId);
            return requireWorkflow(id);
        });
    }
    public synchronized WorkflowStart createIdempotentWorkflow(LabUser user, String orderId, String action, String key) {
        return db.transaction(() -> {
            String mapKey = user.id() + "|" + key;
            String fingerprint = orderId + "|" + action;
            List<IdempotencyRecord> records = db.query("SELECT * FROM idempotency WHERE key=?",
                    r -> new IdempotencyRecord(r.getString("fingerprint"), r.getString("workflow_id")), mapKey);
            if (!records.isEmpty()) {
                IdempotencyRecord existing = records.getFirst();
                if (!existing.fingerprint().equals(fingerprint))
                    throw new LabApiException(HttpStatus.CONFLICT, "IDEMPOTENCY_KEY_REUSED", "The idempotency key was already used for a different request");
                return new WorkflowStart(requireWorkflow(existing.workflowId()), true);
            }
            WorkflowExecution created = createWorkflow(user, orderId, action);
            db.update("INSERT INTO idempotency VALUES (?,?,?)", mapKey, fingerprint, created.getId());
            return new WorkflowStart(created, false);
        });
    }
    public synchronized Optional<WorkflowExecution> findWorkflow(String id) {
        return db.query("SELECT * FROM workflows WHERE id=?", this::workflow, id).stream().findFirst();
    }
    public synchronized List<WorkflowExecution> listWorkflows() { return db.query("SELECT * FROM workflows ORDER BY id", this::workflow); }
    public synchronized WorkflowExecution callback(String id, String status, boolean rejectReplay) {
        return db.transaction(() -> {
            WorkflowExecution execution = requireWorkflow(id);
            if (rejectReplay && execution.getCallbackCount() > 0)
                throw new LabApiException(HttpStatus.CONFLICT, "CALLBACK_ALREADY_HANDLED", "The workflow callback has already been handled");
            db.update("UPDATE workflows SET status=?,callback_count=callback_count+1 WHERE id=?", status, id);
            return requireWorkflow(id);
        });
    }
    public synchronized List<OrderRecord> search(LabUser user, String term, boolean safe) {
        if (safe) return db.query("SELECT * FROM orders WHERE tenant_id=? AND (owner_id=? OR ?='ADMIN') AND item LIKE ? ORDER BY id",
                this::order, user.tenantId(), user.id(), user.role().name(), "%" + term + "%");
        // DELIBERATE SQLi: user input changes the predicate, including tenant filtering.
        try {
            return db.query("SELECT * FROM orders WHERE tenant_id=? AND item LIKE '%" + term + "%' ORDER BY id", this::order, user.tenantId());
        } catch (LabDatabase.DatabaseException e) { throw invalidQuery(); }
    }
    public synchronized int changeStatus(LabUser user, String selector, String status, boolean safe) {
        // Status is bound in BOTH versions; only the vulnerable selector is concatenated.
        if (safe) {
            OrderRecord order = requireOrder(selector);
            if (!order.getTenantId().equals(user.tenantId()) || !order.getOwnerId().equals(user.id()))
                throw new LabApiException(HttpStatus.FORBIDDEN, "ACCESS_DENIED", "Only the owner can submit this order");
            if (!order.getStatus().equals("DRAFT"))
                throw new LabApiException(HttpStatus.CONFLICT, "ORDER_NOT_EDITABLE", "Only draft orders may be submitted");
            return db.update("UPDATE orders SET status=?,version=version+1 WHERE id=? AND tenant_id=? AND owner_id=? AND status='DRAFT'",
                    status, selector, user.tenantId(), user.id());
        }
        // DELIBERATE SQLi: injected OR can bypass every ownership/state predicate.
        try {
            return db.update("UPDATE orders SET status=?,version=version+1 WHERE tenant_id=? AND owner_id=? AND status='DRAFT' AND id='" + selector + "'",
                    status, user.tenantId(), user.id());
        } catch (LabDatabase.DatabaseException e) { throw invalidQuery(); }
    }
    private LabApiException invalidQuery() {
        return new LabApiException(HttpStatus.BAD_REQUEST, "INVALID_ORDER_QUERY", "Order query could not be processed");
    }
    private OrderRecord requireOrder(String id) {
        return findOrder(id).orElseThrow(() -> new LabApiException(HttpStatus.NOT_FOUND, "ORDER_NOT_FOUND", "Order was not found"));
    }
    private WorkflowExecution requireWorkflow(String id) {
        return findWorkflow(id).orElseThrow(() -> new LabApiException(HttpStatus.NOT_FOUND, "WORKFLOW_NOT_FOUND", "Workflow was not found"));
    }
    public record WorkflowStart(WorkflowExecution execution, boolean replayed) { }
    private record IdempotencyRecord(String fingerprint, String workflowId) { }
}
