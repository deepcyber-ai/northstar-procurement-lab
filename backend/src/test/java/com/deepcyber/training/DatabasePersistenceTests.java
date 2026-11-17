package com.deepcyber.training;

import com.deepcyber.training.store.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import static org.assertj.core.api.Assertions.*;

class DatabasePersistenceTests {
    @TempDir Path directory;
    @Test void stateAndIdempotencySurviveReopeningAndResetIsRepeatable() throws Exception {
        String file = directory.resolve("test.db").toString();
        String workflowId;
        try (LabDatabase db = new LabDatabase(file)) {
            LabStore store = new LabStore(db);
            var alice = store.findUser("alice").orElseThrow();
            store.updateOrder("ORD-A-100", order -> order.setItem("Persisted item"));
            var flow = store.createIdempotentWorkflow(alice,"ORD-A-100","SUBMIT_FOR_APPROVAL","stable-key");
            workflowId = flow.execution().getId();
            store.callback(workflowId,"COMPLETED",true);
            store.changeStatus(alice,"ORD-A-100' OR id='ORD-B-100' -- ","PENDING_APPROVAL",false);
        }
        try (LabDatabase db = new LabDatabase(file)) {
            LabStore store = new LabStore(db);
            var alice = store.findUser("alice").orElseThrow();
            assertThat(store.findOrder("ORD-A-100").orElseThrow().getItem()).isEqualTo("Persisted item");
            assertThat(store.findOrder("ORD-B-100").orElseThrow().getStatus()).isEqualTo("PENDING_APPROVAL");
            assertThat(store.findWorkflow(workflowId).orElseThrow().getCallbackCount()).isEqualTo(1);
            assertThat(store.createIdempotentWorkflow(alice,"ORD-A-100","SUBMIT_FOR_APPROVAL","stable-key").replayed()).isTrue();
            assertThat(store.createWorkflow(alice,"ORD-A-100","REVIEW").getId()).isEqualTo("WF-0002");
            store.reset();
            store.reset();
            assertThat(store.listOrders()).hasSize(4);
            assertThat(store.listUsers()).hasSize(5);
            assertThat(store.listWorkflows()).isEmpty();
            assertThat(store.findOrder("ORD-A-100").orElseThrow().getItem()).isEqualTo("Laptop stand");
        }
    }
    @Test void failedTransactionRollsBack() throws Exception {
        try (LabDatabase db = new LabDatabase(":memory:")) {
            LabStore store = new LabStore(db);
            assertThatThrownBy(() -> db.transaction(() -> {
                db.update("DELETE FROM orders");
                throw new IllegalStateException("simulate failure");
            })).isInstanceOf(IllegalStateException.class);
            assertThat(store.listOrders()).hasSize(4);
        }
    }
}
