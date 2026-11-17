package com.deepcyber.training.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Component;
import org.sqlite.SQLiteDataSource;
import java.nio.file.*;
import java.util.List;

/** Separate database: never reachable by procurement SQL queries. Single backend instance only. */
@Component
public class IdentityDatabase implements UserDetailsService {
    public final JdbcTemplate jdbc;
    public IdentityDatabase(@Value("${lab.identity-path:./identity/identity.db}") String path) throws Exception {
        Files.createDirectories(Path.of(path).toAbsolutePath().getParent());
        SQLiteDataSource ds = new SQLiteDataSource();
        ds.setUrl("jdbc:sqlite:" + path);
        ds.setBusyTimeout(5000);
        jdbc = new JdbcTemplate(ds);
        jdbc.execute("PRAGMA journal_mode=WAL");
        if (jdbc.queryForObject("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='oauth2_authorization'", Integer.class) == 0)
            new ResourceDatabasePopulator(new ClassPathResource("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")).execute(ds);
        jdbc.execute("CREATE TABLE IF NOT EXISTS identity_users (id TEXT PRIMARY KEY,email TEXT UNIQUE,password_hash TEXT NOT NULL)");
        jdbc.execute("CREATE TABLE IF NOT EXISTS refresh_history (hash TEXT PRIMARY KEY,authorization_id TEXT NOT NULL)");
        jdbc.execute("CREATE TABLE IF NOT EXISTS identity_sessions (id TEXT PRIMARY KEY,expires_at INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0)");
        var encoder = new BCryptPasswordEncoder();
        for (String[] user : List.of(
                new String[]{"alice","alice.avery@aster-row.test"}, new String[]{"alex","alex.archer@aster-row.test"},
                new String[]{"admin-a","ada.morgan@aster-row.test"}, new String[]{"bob","bob.baker@beacon-works.test"},
                new String[]{"admin-b","ben.carter@beacon-works.test"})) {
            if (jdbc.queryForObject("SELECT count(*) FROM identity_users WHERE id=?",Integer.class,user[0]) == 0)
                jdbc.update("INSERT INTO identity_users VALUES (?,?,?)",user[0],user[1],encoder.encode("Welcome123!"));
        }
    }
    @Override public UserDetails loadUserByUsername(String email) {
        return jdbc.query("SELECT * FROM identity_users WHERE email=?", (r,n) ->
                User.withUsername(r.getString("id")).password(r.getString("password_hash")).roles("USER").build(),
                email.trim().toLowerCase(java.util.Locale.ROOT)).stream().findFirst()
                .orElseThrow(() -> new UsernameNotFoundException("Unknown account"));
    }
}
