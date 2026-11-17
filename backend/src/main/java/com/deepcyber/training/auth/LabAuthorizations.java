package com.deepcyber.training.auth;

import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;

/** Persist standard Spring grants; retain only hashes of refresh tokens, including spent tokens. */
public class LabAuthorizations implements OAuth2AuthorizationService {
    private final JdbcOAuth2AuthorizationService delegate;
    private final IdentityDatabase database;
    public LabAuthorizations(IdentityDatabase database, RegisteredClientRepository clients) {
        this.database = database;
        this.delegate = new JdbcOAuth2AuthorizationService(database.jdbc, clients);
    }
    public static String hash(String value) {
        try { return "sha256:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }
    @Override public synchronized void save(OAuth2Authorization a) {
        var refresh = a.getRefreshToken();
        if (refresh != null) {
            var token = refresh.getToken();
            String hashed = token.getTokenValue().startsWith("sha256:") ? token.getTokenValue() : hash(token.getTokenValue());
            database.jdbc.update("INSERT OR IGNORE INTO refresh_history VALUES (?,?)", hashed,a.getId());
            database.jdbc.update("INSERT OR IGNORE INTO identity_sessions(id,expires_at) VALUES (?,?)",a.getId(),token.getExpiresAt().getEpochSecond());
            if (refresh.isInvalidated()) revoke(a.getId());
            a = OAuth2Authorization.from(a).token(new OAuth2RefreshToken(hashed,token.getIssuedAt(),token.getExpiresAt()),
                    m -> m.putAll(refresh.getMetadata())).build();
        }
        delegate.save(a);
    }
    @Override public synchronized void remove(OAuth2Authorization a) { revoke(a.getId()); delegate.remove(a); }
    @Override public synchronized OAuth2Authorization findById(String id) { return delegate.findById(id); }
    @Override public synchronized OAuth2Authorization findByToken(String token, OAuth2TokenType type) {
        if (token == null) return null;
        if (type == null || OAuth2TokenType.REFRESH_TOKEN.equals(type)) {
            String hashed = hash(token);
            var a = delegate.findByToken(hashed, OAuth2TokenType.REFRESH_TOKEN);
            if (a != null) {
                if (!active(a.getId())) return null;
                var refresh = a.getRefreshToken();
                return OAuth2Authorization.from(a).token(new OAuth2RefreshToken(token,refresh.getToken().getIssuedAt(),refresh.getToken().getExpiresAt()),
                        m -> m.putAll(refresh.getMetadata())).build();
            }
            var prior = database.jdbc.queryForList("SELECT authorization_id FROM refresh_history WHERE hash=?",String.class,hashed);
            if (!prior.isEmpty()) { revoke(prior.getFirst()); return null; }
            if (OAuth2TokenType.REFRESH_TOKEN.equals(type)) return null;
        }
        return delegate.findByToken(token,type);
    }
    public synchronized boolean active(String id) {
        if (id == null) return false;
        return database.jdbc.queryForObject("SELECT count(*) FROM identity_sessions WHERE id=? AND revoked=0 AND expires_at>?",
                Integer.class,id,Instant.now().getEpochSecond()) == 1;
    }
    public synchronized void revoke(String id) { database.jdbc.update("UPDATE identity_sessions SET revoked=1 WHERE id=?",id); }
    public synchronized Instant expires(String id) {
        var rows=database.jdbc.queryForList("SELECT expires_at FROM identity_sessions WHERE id=?",Long.class,id);
        return rows.isEmpty()? null:Instant.ofEpochSecond(rows.getFirst());
    }
}
