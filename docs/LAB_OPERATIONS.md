# Running and resetting the Northstar lab

Northstar is intentionally vulnerable. Run it on an isolated Docker host, use
only its synthetic data and keep its loopback port bindings. Neither Vulnerable
nor Fixed mode is a production configuration.

## Owner controls

First installation uses `python3 owner-control/configure_owner.py` to create a
private salted credential digest in `owner-control/.env`. It prompts for a
password of at least 16 characters and refuses to overwrite an existing file.

Open <http://localhost:8081/demo> as `owner`, then open the vulnerability
controls. This is a separate browser origin from <http://localhost:8080> and
is outside the scanner's target scope. Do not supply its credentials to ARTEX,
Strix or another testing tool.

| Selection | Meaning |
|---|---|
| Enable all — Vulnerable | Enables all 17 seeded exercises. This is the initial profile. |
| Disable all — Fixed | Uses the corrected implementations on the ordinary application routes. |
| Individual switches | Enables only the selected exercises. |

All users share the profile. The backend reads its effective policy on requests;
the SPA polls for changes. Verify actual behaviour after changing a switch.
A missing or invalid configured profile disables the seeded flaws instead of
retaining stale vulnerable settings.

Selecting Fixed does not reset orders, remove stored scripts, revoke tokens
or undo code already run in a browser. Close old vulnerable tabs and use fresh
browser contexts. The always-fixed `/api/secure/*` routes are useful comparisons,
but testing those instead of the original route does not prove the original
route is fixed.

Network restrictions, owner authentication and worker containment remain in
place regardless of profile. The [catalogue](KNOWN_VULNERABILITIES.md) describes
the individual exercises and expected outcomes.

## Authentication and browser state

The Angular SPA uses OAuth authorization code with S256 PKCE and OpenID Connect
against Spring Authorization Server in the backend JVM. This is a lab-specific
provider configuration, not a production identity product.

- Origin and issuer: `http://localhost:8080`.
- Callback: `http://localhost:8080/callback`.
- Discovery: `/.well-known/openid-configuration`.
- Public client: `northstar-spa`; no client secret.
- Access token: signed JWT for the API, with a 24-hour lifetime.
- ID token: signed identity JWT, not an API credential.
- Refresh token: rotates within a seven-day absolute session-family lifetime.
- The frontend keeps tokens and temporary OIDC state in tab-scoped
  `sessionStorage`; the identity provider also has an HttpOnly session cookie.

The refresh-token behaviour is an explicit lab extension for a public SPA
client. Browser-readable storage is intentionally relevant to the XSS exercise;
it is not a secure vault. A cookie/localStorage-only export is not a complete
Northstar session export.

Use separate browser profiles for Alice and Bob. Sign in normally and verify
the returned identity before using an access token. Sign-out revokes that
session family; refreshing with an already-used refresh token also revokes it.
A fresh retest should obtain new sessions, not reuse revoked exports.

### PKCE exercise

AUTH-01 permits an entirely absent `code_verifier` at token exchange when
enabled. It still requires a valid, unexpired, unused authorization code, its
registered client and redirect, and an S256 challenge at authorization.
Wrong or empty verifiers remain rejected. Fixed mode also rejects an absent
verifier. Start a new authorization flow for each comparison; a consumed code
cannot be reused as evidence.

To verify this exercise in the isolated lab, capture and pause a synthetic
account's token request before it reaches the server. Omit the verifier and
send it once. Compare enabled and disabled AUTH-01 using separate fresh flows.
Do not treat this as an authentication bypass without the prerequisite code.

## Persistence

Named Docker volumes keep business records, the identity database, signing
keys and the owner profile separately. Restarting containers preserves these
volumes. Approval workflows are simulated in the backend; no separate workflow
engine or database server is required.

The SQLite databases are single-instance lab storage. Do not copy a live
database file while its WAL may be changing; stop the relevant service first.
Do not commit or distribute databases, signing keys, private environment files,
session exports or assessment results.

## Resetting the lab

Export evidence and stop active tests first. All testers share the data.
There are two different resets:

### Business-data reset

This restores the five synthetic users' business profiles and four seed orders,
and clears workflow history, idempotency records, notes and mutable supplier
script content. It does **not** reset identity sessions, signing keys, owner
switches or worker filesystem state.

The API is disabled by default. To enable it, place a random secret of at least
32 characters in `LAB_RESET_TOKEN` in the private root `.env`. Generate a
suitable value with `openssl rand -hex 32`, keep it private, then apply the
configuration with `docker compose up -d backend`. This recreates the backend
if its environment changed and can interrupt sessions.

The operator can call the reset without putting the secret in process arguments:

```bash
python3 - <<'PY'
import getpass
import json
import urllib.request

token = getpass.getpass("Lab reset secret: ")
if len(token) < 32:
    raise SystemExit("A configured reset secret of at least 32 characters is required.")
request = urllib.request.Request(
    "http://localhost:8080/api/lab/reset", data=b"", method="POST",
    headers={"X-Lab-Reset-Token": token,
             "X-Lab-Confirm-Reset": "RESET-SYNTHETIC-DATA"})
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(request, timeout=10) as response:
    result = json.load(response)
print("Business data reset:", result.get("reset") is True)
PY
```

This permanently deletes changed business data unless it was backed up.
Ordinary user or administrator access tokens cannot authorize reset. Do not
give the reset secret to a scanner.

### Complete fresh installation

For an entirely disposable lab, the following removes **all named volumes
belonging to this Compose project** and then creates new seeded state:

```bash
docker compose ps
docker compose down -v
docker compose up --build -d
```

Run only from the intended project directory, with the same project selection
used to start it. Confirm you are not operating another deployment.
This deletes business data, identity grants, signing keys, profile settings
and shared worker scratch state, invalidating old tokens. It is not reversible
without a backup. The private owner credential file remains on the host, and
the new profile starts Vulnerable.

After command-injection exercises, a business-only reset is insufficient to
clear worker effects. For this disposable release lab, use the complete reset
after saving evidence. Never use broad Docker prune commands.

## Normal shutdown

`docker compose down` stops this project without deleting its volumes.
`docker compose up -d` brings it back. Keep prior evidence outside container
storage and private; do not include it in a source release.
