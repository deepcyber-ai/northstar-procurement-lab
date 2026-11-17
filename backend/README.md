# Deep Cyber Sample backend

> **TRAINING ONLY — DELIBERATELY VULNERABLE.** Do not deploy this application to production,
> expose it to the public internet, connect it to real customer data, or reuse its authentication
> design. Run it only in an isolated, disposable lab.

This Java 21/Spring Boot service is a deterministic target for authorized security-tool training. Data is
persisted in SQLite and seeded on first start. The unsafe routes demonstrate specific flaws; equivalent
`/api/secure/*` routes demonstrate narrowly scoped corrections. They are teaching comparisons,
not a production security framework.

The intended lab default is **Vulnerable**, with each seeded flaw enabled. Owner-only switches select the
**Fixed** implementation for individual exercises, or all exercises together. Fixed mode means the documented
exercise corrections are active; it is **not** a production-hardening or security-certification claim. Explicit
`/api/secure/*` comparison routes remain fixed regardless of switch settings. Network restrictions, separate
owner credentials and export-worker isolation are never switched off. A configured but missing/invalid policy
fails fixed rather than retaining stale enabled flags.

## Run

With Maven and Java 21:

```bash
mvn test
LAB_TRAINING_MODE=true mvn spring-boot:run
```

Or build the isolated container:

```bash
docker build -t deep-cyber-sample-backend .
docker run --rm -p 127.0.0.1:8080:8080 -e LAB_TRAINING_MODE=true \
  --mount type=volume,source=northstar-backend-data,target=/app/data deep-cyber-sample-backend
```

The server listens on port `8080`. Keep the host binding on loopback unless the surrounding lab
provides a private Docker network. `GET /health` and the gateway-friendly `GET /api/health` return
the readiness state and training banner.

For direct cross-origin development or an AWS deployment, set `LAB_ALLOWED_ORIGIN_PATTERNS` to a
comma-separated allowlist, for example `https://d111111abcdef8.cloudfront.net,https://lab.example.test`.
The default remains `http://localhost:*`. When the SPA and API share one CloudFront origin, browsers
do not require CORS and the exact public application origin should still be the only configured value.

## Seeded users and data

See [lab persistence and reset](../docs/LAB_OPERATIONS.md#persistence) for storage configuration,
the separately authenticated reset API, and the SQL injection exercises.
Restarting the backend no longer resets records.

| User | Email | Organisation | Role | Seeded order |
|---|---|---|---|---|
| Alice Avery | `alice.avery@aster-row.test` | Aster & Row | `USER` | `ORD-A-100` |
| Alex Archer | `alex.archer@aster-row.test` | Aster & Row | `USER` | `ORD-A-200` |
| Ada Morgan | `ada.morgan@aster-row.test` | Aster & Row | `ADMIN` | — |
| Bob Baker | `bob.baker@beacon-works.test` | Beacon Works | `USER` | `ORD-B-100` |
| Ben Carter | `ben.carter@beacon-works.test` | Beacon Works | `ADMIN` | `ORD-B-200` |

All seeded users use the synthetic password `Welcome123!`, BCrypt-hashed in a
separate identity database. Sign in through Northstar Login using OAuth code
flow with PKCE. API requests require a signed access token; old deterministic
tokens no longer work. See [authentication and browser state](../docs/LAB_OPERATIONS.md#authentication-and-browser-state) for
lifetimes, refresh rotation, storage and the optional missing-verifier flaw.

## API contract

| Method and route | Purpose |
|---|---|
| `GET /api/debug/database-config` | **Vulnerable:** unauthenticated, allowlisted database metadata |
| `GET /api/orders/search?q=...` | **Vulnerable:** read SQL injection |
| `POST /api/orders/submit` | **Vulnerable:** data-modifying SQL injection in `orderId` |
| `POST /api/lab/reset` | Protected management-only transactional seed reset |
| `GET /api/auth/me` | Resolve the signed access token to the current account |
| `POST /api/auth/login` | Retired; returns 410; use OAuth browser sign-in |
| `GET /api/orders` | List the current persona's tenant orders |
| `GET /api/orders/{id}` | **Vulnerable:** authenticated cross-tenant IDOR |
| `PATCH /api/orders/{id}` | **Vulnerable:** mass assignment of tenant, owner, price, and status |
| `POST /api/orders/{id}/export` | `CMD-01` selectable export command injection in an isolated worker; ownership always enforced |
| `POST /api/secure/orders/{id}/export` | Fixed `csv`/`json` export with no shell execution |
| `GET /api/admin/overview` | **Vulnerable:** trusts `X-Authenticated-Role` from the gateway |
| `POST /api/tools/fetch-preview` | **Vulnerable simulation:** accepts internal URLs, but performs no network access |
| `POST /api/workflows` | **Vulnerable:** no order authorization or idempotency |
| `GET /api/workflows/{id}` | **Vulnerable:** workflow IDOR |
| `POST /api/workflows/{id}/callback` | **Vulnerable:** unauthorised, replayable callback |
| `GET/PATCH /api/secure/orders...` | Ownership/tenant enforcement and an editable-field allowlist |
| `GET /api/secure/admin/overview` | Uses the seeded authenticated role and tenant scope |
| `POST /api/secure/tools/fetch-preview` | Exact scheme/host/path allowlist; still no network access |
| `POST /api/secure/workflows` | Ownership check, action allowlist, and required `Idempotency-Key` |
| `GET /api/secure/workflows/{id}` | Tenant and ownership enforcement |
| `POST /api/secure/workflows/{id}/callback` | Callback token, terminal-state allowlist, and replay rejection |

The workflow request shape is:

```json
{
  "orderId": "ORD-A-100",
  "action": "SUBMIT_FOR_APPROVAL"
}
```

The workflow response shape is consistent across unsafe and secure routes:

```json
{
  "id": "WF-0001",
  "orderId": "ORD-A-100",
  "tenantId": "tenant-a",
  "requestedBy": "alice",
  "action": "SUBMIT_FOR_APPROVAL",
  "status": "RUNNING",
  "executionNumber": 1,
  "callbackCount": 0,
  "createdAt": "2026-01-01T00:00:00Z"
}
```

For the secure start route, use an 8–128 character `Idempotency-Key`. A repeated identical request
returns the original workflow with `X-Idempotent-Replay: true`. Fixed callbacks require a separately
configured `LAB_CALLBACK_TOKEN` of at least 32 characters; without it, that callback route is disabled.

## Gateway training flaw

The intended gateway copies the attacker-controlled `X-Training-Role` header into
`X-Authenticated-Role`. The vulnerable admin endpoint trusts that resulting header. The secure
endpoint ignores it and looks up the actual role attached to the selected persona. This models a
gateway/backend trust differential without any cloud dependency.

## Safe SSRF simulation

`MockFetchService` deliberately imports no HTTP client, opens no socket, performs no DNS lookup,
and always returns `networkAccessPerformed: false`. Requests for `metadata.internal`,
`orders.internal`, or `169.254.169.254` return fake training strings. This preserves the learning
signal without enabling the lab to reach cloud metadata or arbitrary network targets.

## Isolated export worker

Command execution is deliberately **not** implemented in this Spring/identity JVM. `ExportWorkerService`
sends a bounded newline-JSON request over a Unix socket to the separate network-disabled worker. Only
the order ID and requested export format are sent; the worker exports fixed synthetic fixture data. Item text,
notes, tokens, database files and identity keys are never forwarded or mounted there. Both export routes
enforce real tenant/owner access even if the object-authorization vulnerability is enabled elsewhere.

In vulnerable mode, `{"format":"csv; printf CMD01_PROOF"}` demonstrates the flaw using a harmless marker.
In fixed mode, only `csv` and `json` are accepted and no subprocess is launched. A missing or unresponsive
worker returns 503; there is no fallback to execution inside the backend. Worker output is untrusted plain text.

See [export worker deployment and tests](../export-worker/README.md) for mandatory limits and the four-second
Java transport deadline. A data seed reset does **not** reverse arbitrary commands inside the worker.
`ExportWorkerService.reset()` can remove a small fixed set of scratch files for trusted management code;
**recreate the export-worker container and its dedicated socket volume for a complete worker reset**.
Stop/recreate the backend too to release its read-only socket mount, and do not remove application, identity,
signing-key or policy volumes. Restarting only the worker does not clear a still-mounted shared socket volume.
No ordinary-user reset API is exposed.

## Test coverage

The MockMvc suite verifies:

- the training-only banner and login contract;
- vulnerable versus secure cross-tenant order access;
- protected-field mass assignment;
- gateway role-header spoofing versus identity-based admin authorization;
- simulated SSRF with no outbound network and the secure allowlist;
- duplicate workflow creation versus idempotent execution;
- workflow tenant checks and callback replay rejection; and
- CORS support for a local Angular development origin and configurable exact
  cloud origins, including rejection of an unconfigured origin.

Additional export tests cover server-selected feature flags, authentication and cross-tenant denial,
fixed-format validation, missing-worker fail-closed behavior, socket response/framing/output bounds and
overall transport deadlines. The worker's Python suite separately covers the real marker proof, fixed no-shell
path, subprocess time/output limits, Linux descendant cleanup and restricted scratch reset.
