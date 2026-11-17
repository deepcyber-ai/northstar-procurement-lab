package com.deepcyber.training.store;

import jakarta.annotation.PreDestroy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

/** One local database connection. LabStore serialises application operations. */
@Component
public class LabDatabase implements AutoCloseable {
    private final Connection connection;

    public LabDatabase(@Value("${lab.database-path:./data/northstar.db}") String path) {
        try {
            if (!path.equals(":memory:")) Files.createDirectories(Path.of(path).toAbsolutePath().getParent());
            connection = DriverManager.getConnection("jdbc:sqlite:" + path);
            try (Statement statement = connection.createStatement()) {
                statement.execute("PRAGMA busy_timeout=5000");
                statement.execute("PRAGMA foreign_keys=ON");
                statement.execute("PRAGMA journal_mode=WAL");
                statement.execute("PRAGMA synchronous=FULL");
            }
            transaction(() -> {
                int version = query("PRAGMA user_version", rs -> rs.getInt(1)).getFirst();
                if (version > 3) throw new IllegalStateException("Unsupported database schema version");
                if (version == 0) {
                    update("CREATE TABLE users (id TEXT PRIMARY KEY, name TEXT, email TEXT UNIQUE, tenant TEXT, organization TEXT, title TEXT, role TEXT, password TEXT)");
                    update("CREATE TABLE orders (id TEXT PRIMARY KEY, tenant_id TEXT, owner_id TEXT, item TEXT, quantity INTEGER, unit_price TEXT, status TEXT, workflow_starts INTEGER, version INTEGER)");
                    update("CREATE TABLE workflows (id TEXT PRIMARY KEY, order_id TEXT, tenant_id TEXT, requested_by TEXT, action TEXT, status TEXT, execution_number INTEGER, callback_count INTEGER, created_at TEXT)");
                    update("CREATE TABLE idempotency (key TEXT PRIMARY KEY, fingerprint TEXT, workflow_id TEXT)");
                    update("CREATE TABLE metadata (key TEXT PRIMARY KEY, value INTEGER)");
                    update("PRAGMA user_version=1");
                }
                if (version < 2) {
                    update("ALTER TABLE users DROP COLUMN password");
                    update("PRAGMA user_version=2");
                }
                if (version < 3) {
                    update("CREATE TABLE order_notes (order_id TEXT PRIMARY KEY REFERENCES orders(id) ON DELETE CASCADE, html TEXT NOT NULL)");
                    update("CREATE TABLE vendor_widget (id INTEGER PRIMARY KEY CHECK (id=1), script TEXT NOT NULL)");
                    update("PRAGMA user_version=3");
                }
                return null;
            });
        } catch (Exception e) {
            throw new IllegalStateException("Unable to initialise lab database", e);
        }
    }

    public <T> List<T> query(String sql, RowMapper<T> mapper, Object... parameters) {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            bind(statement, parameters);
            try (ResultSet rows = statement.executeQuery()) {
                List<T> result = new ArrayList<>();
                while (rows.next()) result.add(mapper.map(rows));
                return result;
            }
        } catch (SQLException e) { throw new DatabaseException(e); }
    }

    public int update(String sql, Object... parameters) {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            bind(statement, parameters);
            return statement.executeUpdate();
        } catch (SQLException e) { throw new DatabaseException(e); }
    }

    public <T> T transaction(Supplier<T> operation) {
        try {
            // Nested operations participate in the outer transaction.
            if (!connection.getAutoCommit()) return operation.get();
            connection.setAutoCommit(false);
            try {
                T result = operation.get();
                connection.commit();
                return result;
            } catch (RuntimeException | Error e) {
                connection.rollback();
                throw e;
            } finally { connection.setAutoCommit(true); }
        } catch (SQLException e) { throw new DatabaseException(e); }
    }

    private void bind(PreparedStatement statement, Object[] parameters) throws SQLException {
        for (int i = 0; i < parameters.length; i++) statement.setObject(i + 1, parameters[i]);
    }

    @PreDestroy
    public void close() throws SQLException { connection.close(); }

    @FunctionalInterface
    public interface RowMapper<T> { T map(ResultSet row) throws SQLException; }
    public static class DatabaseException extends RuntimeException {
        public DatabaseException(SQLException cause) { super("Database operation failed", cause); }
    }
}
