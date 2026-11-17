package com.deepcyber.training.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/** Lab-owned supplier integration, not an external vendor or third-party package. */
public final class SupplierWidget {
    private SupplierWidget() { }
    // Exact immutable bytes are also pinned in the frontend. Never hash the mutable database copy.
    public static final String TRUSTED_SCRIPT = "(() => { const host = document.getElementById('northstar-supplier-widget'); if (host) { const text = document.createElement('p'); text.textContent = 'Northstar Supply Network · Standard delivery: 3–5 working days'; host.replaceChildren(text); } })();\n";
    public static final String INTEGRITY = integrity();

    private static String integrity() {
        try {
            return "sha384-" + Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-384")
                    .digest(TRUSTED_SCRIPT.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
}
