package com.deepcyber.training;

import com.deepcyber.training.service.SupplierWidget;
import com.deepcyber.training.store.LabDatabase;
import com.deepcyber.training.store.LabStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.DriverManager;

import static org.assertj.core.api.Assertions.assertThat;

class ContentPersistenceTests {
    @TempDir Path directory;

    @Test void notesAndWidgetSurviveReopenAndResetClearsBoth() throws Exception {
        String file = directory.resolve("content.db").toString();
        try (LabDatabase db = new LabDatabase(file)) {
            LabStore store = new LabStore(db);
            store.saveOrderNotes("ORD-A-100", "<b>Saved purchasing note</b>");
            store.saveVendorWidget("document.body.dataset.northstarSupplyChain='seen';");
        }
        try (LabDatabase db = new LabDatabase(file)) {
            LabStore store = new LabStore(db);
            assertThat(store.orderNotes("ORD-A-100")).isEqualTo("<b>Saved purchasing note</b>");
            assertThat(store.vendorWidget(SupplierWidget.TRUSTED_SCRIPT)).contains("northstarSupplyChain");
            store.reset();
            assertThat(store.orderNotes("ORD-A-100")).doesNotContain("Saved purchasing note");
            assertThat(store.vendorWidget(SupplierWidget.TRUSTED_SCRIPT)).isEqualTo(SupplierWidget.TRUSTED_SCRIPT);
        }
    }

    @Test void schemaTwoUpgradePreservesOrdersAndCreatesContentTables() throws Exception {
        String file = directory.resolve("migration.db").toString();
        try (LabDatabase db = new LabDatabase(file)) {
            LabStore store = new LabStore(db);
            store.updateOrder("ORD-A-100", order -> order.setItem("Existing purchase order"));
        }
        try (var connection = DriverManager.getConnection("jdbc:sqlite:" + file); var statement = connection.createStatement()) {
            statement.execute("DROP TABLE order_notes");
            statement.execute("DROP TABLE vendor_widget");
            statement.execute("PRAGMA user_version=2");
        }
        try (LabDatabase db = new LabDatabase(file)) {
            LabStore store = new LabStore(db);
            assertThat(store.findOrder("ORD-A-100").orElseThrow().getItem()).isEqualTo("Existing purchase order");
            store.saveOrderNotes("ORD-A-100", "Migrated successfully");
            assertThat(store.orderNotes("ORD-A-100")).isEqualTo("Migrated successfully");
            assertThat(store.vendorWidget(SupplierWidget.TRUSTED_SCRIPT)).isEqualTo(SupplierWidget.TRUSTED_SCRIPT);
        }
    }
}
