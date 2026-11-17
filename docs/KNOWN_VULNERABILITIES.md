# Northstar Procurement — Known Vulnerabilities

**Audience:** lab operators, authorised penetration testers, and security-tool evaluators  
**Baseline:** runtime-switchable lab source, reviewed 31 October 2026  
**Classification:** lab answer material — contains assessment spoilers

## 1. Purpose and verification status

Northstar is a deliberately vulnerable procurement application with synthetic
users, organisations, purchase orders and approval workflows. This document
catalogues the intended findings, their business impact, expected evidence,
safe comparisons and important limits.

This is an implementation-backed assessment reference, **not a penetration-test
report confirming every issue on a live AWS deployment**. The runtime-toggle,
stored-XSS, widget and export-worker changes require a coordinated deployment;
their presence in this repository does not establish that an existing AWS
instance has them. Confirm its build and effective configuration before testing.
See [release notes](RELEASE_NOTES.md) for this candidate's verification status.

For a genuinely blind assessment, give the tester the application URL, authorised
accounts and scope—not this document, source code or the answer key. Use this
catalogue afterwards to assess coverage and false positives.

### Vulnerable, Fixed and Custom profiles

The intended initial lab profile is **Vulnerable**: all 17 switches enabled.
The separate owner-only control page can enable all, disable all (**Fixed**),
or save individual switches (**Custom**). An enabled switch means the defect
is present; disabling it selects the corrected implementation on the same
ordinary application route. Existing `/api/secure/...` comparisons remain fixed
regardless of profile. GW-02 applies only to the Nginx gateway variant.

`LAB_TRAINING_MODE=false` forces every flag off. With no configuration file,
`LAB_VULNERABILITIES_DEFAULT=all|fixed` selects the starting behavior, defaulting
to `all` only when training mode is true. When `LAB_VULNERABILITY_CONFIG_PATH`
is configured, missing, unreadable, oversized or invalid JSON disables all flags;
the backend never retains a previously enabled policy after a bad file read.
Owner changes are read-only to the target application and are not a user API.

Changing profiles does not reset records, revoke tokens or undo JavaScript
already executed in a browser. Reset state and start a fresh browser context
for clean comparisons. **Fixed means these seeded defects are disabled—not that
the lab has become production-ready.** IP restrictions, owner authentication,
worker containment and reset protection are never disabled by Enable all.

## 2. Application and trust boundaries

The Angular SPA calls a single Spring Boot backend through a gateway. SQLite
persists users, orders, purchasing notes, a lab-owned supplier widget, workflow
history and idempotency records. Approval
execution is simulated inside the backend; there is no separate workflow
microservice or real AWS Step Functions integration. A separate, network-isolated
export worker provides the command-injection exercise. The Spring/IdP JVM never
executes the injected command. The separate owner control service stores flags,
not application data, and is outside the pentest target scope.

There are two gateway architectures:

- **Containerised:** Nginx routes browser requests to frontend and backend
  containers. The single-EC2 option uses this same stack.
- **AWS-native:** CloudFront and WAF serve the SPA from private S3 and route API
  requests through API Gateway, a VPC Link and an internal ALB to the backend.

The main boundaries under test are browser-to-gateway, gateway-to-service,
user-to-role, organisation-to-organisation, application-to-database and
caller-to-workflow callback.

The business API remains a single Spring backend. The worker is separated for
containment, not to imply a distributed workflow engine. Its Unix-socket boundary
is deliberately narrower than a general-purpose network microservice.

### Personas used in examples

| Persona | Organisation | Role |
|---|---|---|
| Alice Avery | Aster & Row / `tenant-a` | Standard user |
| Alex Archer | Aster & Row / `tenant-a` | Standard user |
| Ada Morgan | Aster & Row / `tenant-a` | Administrator |
| Bob Baker | Beacon Works / `tenant-b` | Standard user |
| Ben Carter | Beacon Works / `tenant-b` | Administrator |

Use [the user guide](USER_GUIDE.md) for login details and normal journeys.
Alice's seed order is `ORD-A-100`; Bob's is `ORD-B-100`. There are four
orders in a freshly reset database.

## 3. Vulnerability register

“Authenticated” below means a valid synthetic bearer identity; its weaknesses
are discussed separately in section 5. Network access to the lab is always
required, including for unauthenticated endpoints.

| ID | Known weakness | Entry point | Prerequisite / deployment | Expected evidence |
|---|---|---|---|---|
| API-01 | Cross-organisation order access (IDOR/BOLA) | `GET /api/orders/{id}` | Authenticated; either architecture | Alice receives Bob's order |
| API-02 | Mass assignment of protected order properties | `PATCH /api/orders/{id}` | Authenticated owner of the order | Price, tenant, owner or status changes through client-supplied fields |
| GW-01 | Privilege escalation through a client-controlled role header | `GET /api/admin/overview` | Authenticated; gateway role mapping enabled | Standard user obtains an all-organisation admin summary |
| GW-02 | Exact-path gateway policy misses nested routes | `/api/admin` versus `/api/admin/overview` | Nginx deployment | Root policy does not protect the actual nested operation |
| GW-03 | Arbitrary credentialed CORS reflection | Non-secure API routes | Backend dynamic CORS; verify upstream gateway forwards policy | Untrusted Origin reflected with credentials permitted |
| API-03 | Unsafe URL acceptance — SSRF simulation | `POST /api/tools/fetch-preview` | Authenticated; either architecture | Private/metadata-shaped URL accepted, but no network access occurs |
| WF-01 | Cross-organisation workflow initiation | `POST /api/workflows` | Authenticated; another organisation's order ID | Workflow created against an unauthorised order |
| WF-02 | Missing workflow-start idempotency | `POST /api/workflows` | Authenticated; repeat identical request | Same idempotency key produces distinct workflow IDs |
| WF-03 | Cross-organisation workflow disclosure | `GET /api/workflows/{id}` | Authenticated; another user's workflow ID | Unauthorised workflow details returned |
| WF-04 | Unauthorised callbacks, weak status validation and replay | `POST /api/workflows/{id}/callback` | Any authenticated user | Arbitrary status accepted and repeated callbacks increment the count |
| DB-01 | Unauthenticated database configuration disclosure | `GET /api/debug/database-config` | New SQLite version; lab mode enabled | SQLite metadata returned without login |
| SQL-01 | Read SQL injection | `GET /api/orders/search?q=...` | Authenticated; new SQLite version; lab mode | Injected search returns orders across organisations |
| SQL-02 | Data-modifying SQL injection | `POST /api/orders/submit` | Authenticated; new SQLite version; lab mode | Injected selector changes other organisations' order states |
| AUTH-01 | PKCE missing-verifier bypass | `POST /auth/token` | Flag enabled; valid intercepted unused code | Code exchange succeeds without the verifier; fixed mode rejects |
| XSS-01 | Stored XSS through Angular sanitizer bypass | Order purchasing notes / `PUT /api/orders/{id}/notes` | Own order write access; a permitted viewer opens its notes | Harmless script marker executes in app origin |
| SC-01 | Lab-owned supplier script publishing and missing integrity | `PUT /api/vendor/widget`; supplier insight widget | Any authenticated persona can publish while enabled | Modified lab-owned script executes on widget reload |
| CMD-01 | OS command injection in isolated export worker | `POST /api/orders/{id}/export` | Authenticated order access; worker deployed with required containment | Harmless injected marker appears in command output |

These are **17 exercise entries**, not 17 necessarily independent report
findings. GW-01 and GW-02 can form one exploit chain. WF-04 groups several
related callback defects. Report root causes and impacts without inflating counts.
Severity should be justified from demonstrated impact in the assessed
deployment; this catalogue does not assign production CVSS scores to synthetic
data or simulated services.

## 4. Detailed explanations and expected comparisons

### API-01 — Cross-organisation order read

The list endpoint filters orders by organisation, but the vulnerable detail
endpoint checks only that a user is authenticated. Changing the order ID allows
Alice to retrieve Bob's order. A filtered list is not object-level access control.

- **Impact:** disclosure of another organisation's purchasing records.
- **Discovery and proof:** capture an order-detail request, obtain Bob's ID
  through an authorised second account, and request it using Alice's unchanged
  token. Preserve the response showing `tenant-b`.
- **Safe comparison:** `GET /api/secure/orders/{id}` returns 403 for this case.
- **Correction:** enforce organisation and ownership/role policy on every
  object operation, not only list views or frontend navigation.

### API-02 — Mass assignment

The vulnerable update route checks that the caller owns the current order, but
then accepts fields that a normal user should not control: `tenantId`,
`ownerId`, `unitPrice` and `status`.

- **Impact:** price manipulation, self-approval or reassignment of data across
  users and organisations.
- **Proof:** update an owned order with protected properties and retrieve it
  again to confirm the changes. This route is not an unrestricted update of
  any other user's order; the initial ownership check still applies.
- **Safe comparison:** the secure PATCH route accepts only the intended
  editable properties and rejects unknown protected fields with 400. It also
  checks ownership and draft state.
- **Correction:** use explicit request-field allowlists and server-controlled
  transitions. This is an API binding flaw, distinct from SQL injection.

### GW-01 — Client-controlled role becomes trusted identity

The browser sends `X-Training-Role`. Nginx and the AWS API Gateway integration
map that value to `X-Authenticated-Role`. The vulnerable admin handler trusts
the asserted role instead of checking the bearer user's actual role.

- **Impact:** vertical privilege escalation and disclosure of all-organisation
  administrative totals.
- **Proof:** keep Alice's bearer token and send `X-Training-Role: ADMIN`.
  A successful response exposes the all-tenant summary.
- **Safe comparison:** `/api/secure/admin/overview` rejects Alice with 403;
  an actual seeded administrator receives only their organisation's summary.
- **Correction:** derive authorisation from verified identity and discard
  client assertions of trusted roles.

Direct backend comparisons use `X-Authenticated-Role` instead. Test the
origin only if it is explicitly in scope; a public hostname does not authorise
testing every infrastructure endpoint behind it.

### GW-02 — Gateway policy covers only an exact path

Nginx identifies its requests with a gateway-controlled marker. The backend
models the gateway's exact `/api/admin` policy, which always requires a real
administrator. With GW-02 enabled the nested `/api/admin/overview` route misses
that additional check and can be combined with GW-01's trusted role assertion.
Disabling GW-02 covers the subtree even while GW-01 remains enabled. Disabling
GW-01 independently rejects the forged role and scopes real admins to their tenant.

- **Impact:** a gateway restriction fails to cover the operation it was meant
  to protect; it contributes to the role-header escalation chain.
- **Proof:** compare root and nested-path responses, then demonstrate the
  impact with the role-header test. A different status alone is insufficient.
- **Correction:** cover the intended route subtree and methods, and enforce
  authorisation in the backend regardless of gateway policy.

This exact-path defect is specific to the Nginx configuration. Do not report it
against AWS API Gateway merely because the application has the same URLs.

### GW-03 — Reflected credentialed CORS

The backend's switchable API CORS filter reflects an arbitrary request Origin and emits
`Access-Control-Allow-Credentials: true`.

- **Impact:** an unsafe cross-origin policy; in an application using ambient
  cookie authentication, such a policy can expose authenticated responses.
- **Evidence:** inspect preflight and actual response headers for an untrusted
  Origin, then validate browser behaviour before claiming data theft.
- **Important limit:** Northstar keeps its access token in
  origin-isolated sessionStorage. An unrelated website does not automatically
  obtain that token or attach it to requests. Reflected headers alone do not
  prove an authenticated cross-origin compromise.
- **Correction:** use an explicit origin allowlist and permit credentials only
  when required.

Disabling GW-03 uses the configured origin allowlist without credentials.
`/api/secure/...` always uses that fixed policy. It does not affect OAuth routes
or the separate owner origin. Both preflights and actual API responses are
covered; deployment-level CORS overrides must not mask the selected behavior.
Older deployments used Nginx-only reflection, so verify the deployed version.

### API-03 — URL-preview validation / simulated SSRF

The preview route accepts private and metadata-shaped URLs and returns fake
training responses. It performs **no DNS lookup or outbound HTTP request**.

- **Expected result:** an accepted URL with `networkAccessPerformed:false`.
- **Safe comparison:** the secure route rejects the private URL with 400 and
  accepts only the configured simulated public host/scheme/path.
- **Reporting limit:** describe unsafe input acceptance in an SSRF simulator.
  Do not claim actual SSRF, network reachability, AWS metadata access,
  credential theft or cloud-account compromise.
- **Production lesson:** a real fetching service needs destination validation
  and network egress restrictions; the simulator does not validate those controls.

### WF-01 — Cross-organisation workflow initiation

The vulnerable start route does not authorise access to the referenced order.
Alice can submit a workflow request containing Bob's order ID.

- **Impact:** unauthorised approval activity against another organisation's
  purchase order.
- **Proof:** retain the returned workflow ID and show that Bob's order has an
  incremented `workflowStarts` count.
- **Safe comparison:** `POST /api/secure/workflows` returns 403 for Alice
  referencing Bob's order.
- **Correction:** validate access to the referenced business object before
  creating workflow state.

### WF-02 — Missing idempotency on workflow start

The vulnerable route ignores the supplied `Idempotency-Key`. Repeating an
identical request creates a second workflow.

- **Impact:** duplicate approval activity and inconsistent business processing.
  Northstar does not execute real purchases or payments.
- **Proof:** two requests with the same key return distinct workflow IDs and
  increment the backing order's start count twice.
- **Safe comparison:** for an authorised order, the secure route returns 201
  then 200 with the same workflow ID and a replay header. Reusing a key for a
  different request returns 409.
- **Correction:** persist idempotency records and validate request fingerprints.
  The SQLite implementation retains these records across backend restarts.

### WF-03 — Workflow read IDOR

Any authenticated user can read any workflow using its ID, regardless of the
backing order's organisation or owner.

- **Impact:** disclosure of another organisation's approval activity and state.
- **Proof:** create a workflow as Alice and retrieve that ID as Bob.
- **Safe comparison:** the secure GET checks access to the backing order and
  returns 403 to Bob.
- **Correction:** apply object-level authorisation to workflow reads, not just
  workflow creation.

### WF-04 — Unauthorised callback, arbitrary status and replay

The vulnerable callback requires a normal bearer identity, but does not verify
that the caller is an authorised callback service or can access that workflow.
It accepts arbitrary nonblank status text and repeated callbacks.

- **Impact:** a normal user can falsify workflow state, including another
  organisation's workflow, and repeat terminal transitions.
- **Proof:** invoke a callback with an ordinary user's token, inspect the
  changed status, repeat it, and observe `callbackCount`.
- **Safe comparison:** the secure route requires the separate synthetic
  callback token, permits only `COMPLETED` or `FAILED`, and rejects replay
  with 409.
- **Correction:** authenticate callback senders, validate state transitions,
  authorise the relevant resource and prevent replay.

This is **unauthorised**, not wholly unauthenticated, callback access. The
fixed callback requires an operator-configured `LAB_CALLBACK_TOKEN` of at least
32 characters. There is no fallback secret: absent/short configuration disables
fixed callbacks with 404; missing/invalid supplied credentials return 401.

### DB-01 — Database configuration disclosure

The new debug endpoint is enabled in lab mode without authentication.
`robots.txt` discloses its path, making it discoverable in a black-box pass.

- **Information exposed:** SQLite engine name, database filename, a logical
  location, schema version and table names.
- **Impact:** reconnaissance that can inform subsequent database testing.
- **Limits:** this is an allowlisted metadata response, not an environment or
  configuration dump. It exposes no actual host path, management secret, AWS
  credential or database download. SQLite has no remote database-server
  username/password to reveal.
- **Safe comparison:** `/api/secure/debug/database-config` requires the
  separate management secret; normal administrator bearer tokens do not suffice.
- **Correction:** remove debug endpoints from exposed deployments or protect
  them with explicit management authorisation and minimal responses.

### SQL-01 — Read SQL injection in item search

The search implementation concatenates the `q` value into a SQL predicate.
An injected expression can change the query structure and bypass tenant filtering.

- **Discovery:** use **Search items** in the UI and inspect the resulting GET.
- **Example input:** `' OR 1=1 -- `
- **Expected evidence:** Alice's ordinary empty search returns two tenant-a
  orders; the injected search returns all four seeded orders, including tenant-b.
- **Safe comparison:** the same input is a literal search value on
  `/api/secure/orders/search` and returns an empty array. Its query also
  enforces organisation and ownership/administrator policy.
- **Correction:** bind values using prepared statements and retain access
  predicates. Merely using a prepared-statement API is insufficient if user
  input has already been concatenated into the SQL text.

This is real SQL execution, unlike the SSRF simulator. Distinguish it from
API-01 by proving SQL predicate manipulation rather than changing a plain ID.

### SQL-02 — Data-modifying SQL injection in order submission

The submit route concatenates `orderId` into an UPDATE statement. The normal
operation submits an owned draft, setting its status to `PENDING_APPROVAL`.

- **Discovery:** open a draft order, choose **Submit order for approval**, and
  inspect the JSON body sent to `POST /api/orders/submit`.
- **Control:** sending Bob's literal order ID as Alice updates zero records.
- **Injected selector:** `ORD-A-100' OR 1=1 -- `
- **Expected evidence:** the injected request reports four updated rows on a
  fresh dataset. All four orders become `PENDING_APPROVAL`, including Bob's
  order and a previously approved order; their versions increment.
- **Persistence:** changes survive backend restart and container recreation
  when the SQLite volume is retained. Verify Bob's changed record using Bob's
  session rather than relying solely on the update count.
- **Safe comparison:** the secure submit route returns 404 for the injected
  literal ID, 403 for Alice submitting Bob's actual ID, and updates exactly one
  eligible owned draft.
- **Correction:** parameterise the selector and enforce tenant, ownership and
  allowed-state predicates.

This exercise changes actual synthetic data and needs no stacked SQL
statements. The implemented status is fixed and bound by the application:
the demonstrated impact is unauthorised submission/state overwrite, not an
arbitrary SQL-controlled price or approval value. Price changes and direct
self-approval are demonstrated separately by mass assignment.

Order submission changes status; it does not itself create a workflow.
Use the protected reset procedure before subsequent tests.

## 5. Additional authentication weaknesses and lab shortcuts

These are observable security limitations beyond the exercise entries.
They should be acknowledged, not mistaken for a secure authentication baseline.

| Limitation | Explanation | Assessment treatment |
|---|---|---|
| Shared synthetic credentials | Seeded accounts use a documented common password, BCrypt-hashed in the separate identity database | Lab convenience; never use real passwords |
| Browser-readable tokens | Access, ID and refresh tokens are held in sessionStorage | XSS could steal tokens; tab-scoped storage does not protect against executing JavaScript |
| Long access-token lifetime | Access tokens last 24 hours, but family expiry, logout and refresh replay revoke access server-side | Document the lifetime; do not claim indefinite validity or missing revocation |
| Single-process identity | The IdP and business API share one JVM, although their SQLite files and keys are separate | Separate files do not protect identity secrets from arbitrary execution in that JVM; CMD-01 therefore runs elsewhere |

The `/api/secure/...` endpoints are **narrow teaching comparisons**. The Fixed
profile applies corrected implementations to ordinary routes too, but neither
is a claim of production readiness. To compare authorisation meaningfully, hold the
caller's bearer token constant. Substituting another user's legitimately issued
token does not demonstrate an object-level authorization bypass by the original user.

### AUTH-01 — Switchable PKCE missing-verifier bypass

The OAuth version replaces predictable tokens with signed OAuth access tokens.
When the AUTH-01 switch and lab mode are enabled, the
public-client token authentication extension accepts a code exchange with no
`code_verifier`. A supplied wrong/empty verifier still fails. The Vulnerable
profile enables this flaw by default. Fixed mode, or disabling AUTH-01 alone,
rejects the same missing-verifier request without restarting the IdP.
The obsolete `LAB_PKCE_MODE` setting cannot override the owner-controlled policy.

An attacker needs a valid, unused authorization code bound to the registered
client and callback. PKCE would normally prevent exchange without the original
browser's verifier. This defect removes that protection and can permit session
impersonation if code interception is possible. It does not itself provide a
code-interception primitive. Suggested severity: High if that prerequisite is
demonstrated; report the prerequisite explicitly. CWE-287 / OAuth PKCE failure.

See [the controlled reproduction procedure](LAB_OPERATIONS.md#pkce-exercise).
The strict comparison retains the same login, scopes, redirects and code TTL.

Storing a bearer token in browser storage is not, by itself, proof of XSS or
cross-origin token theft. Demonstrate a separate executable script flaw before
making that claim.

### XSS-01 — Stored purchasing notes bypass Angular sanitization

Purchasing notes are persisted as HTML, with real owner/tenant authorization on
their read/write endpoints. In vulnerable mode the Angular notes component
passes the stored string to `bypassSecurityTrustHtml()` before `[innerHTML]`.
This is deliberate application misuse of Angular's trust API, not a defect in
Angular's normal escaping or sanitizer.

- **Impact:** a malicious note executes in the app origin when an authorized
  viewer opens it, potentially acting as that viewer or accessing browser tokens.
- **Proof:** save an image-error handler that sets a harmless DOM marker, then
  inspect that marker after reloading. Use no external callback or real token theft.
- **Fixed comparison:** disable XSS-01; the same stored HTML passes through
  Angular's normal sanitization and its event handler is removed.
- **Important distinction:** the secure notes API stores the same inert data.
  The correction is at the rendering sink, not merely in a different write URL.
- **Reset:** protected business reset clears saved notes; close test tabs as
  well, because switching modes does not remove code already running in memory.

### SC-01 — Controlled client-side supply-chain compromise

The supplier insight widget is a lab-owned script, not a real third-party
dependency or public registry. While enabled, any authenticated purchaser may
replace its contents through `PUT /api/vendor/widget`; the SPA loads that mutable
script without integrity enforcement. This models a compromised distribution
channel plus excessive trust in delivered JavaScript.

- **Impact/proof:** replace the script with a harmless DOM marker and reload
  the widget to prove execution in the consuming application's origin.
- **Fixed comparison:** publishing is rejected with 403 and the frontend adds
  build-pinned SHA-384 SRI to the same script URL. Previously tampered content
  fails integrity and does not execute; reset restores the original widget.
  `/api/secure/vendor/widget.js` separately serves the immutable reference script.
- **Scope:** change only this lab-owned asset. No npm package, vendor account,
  public CDN, real signing key or upstream service is attacked.
- **Evidence:** missing SRI alone is not proof of compromise; demonstrate the
  controlled modification and subsequent execution. Reset restores the default
  script. Existing executing JavaScript requires a fresh browser context.

### CMD-01 — Command injection in an isolated export worker

The ordinary export route accepts an output format. Vulnerable mode interpolates
it into a shell command in a dedicated worker; `csv; printf CMD01_PROOF` produces
a harmless marker in returned text. Fixed mode accepts only `csv` or `json` and
does not start a shell. The secure export route always uses that fixed path.

- **Impact:** actual OS command execution inside the disposable worker, not
  a simulated success string and not execution in the Spring/IdP process.
- **Mandatory boundary:** no IP network, cloud credentials, app/identity/key
  mounts, host mounts or Docker socket; non-root, read-only root, dropped
  capabilities, default seccomp, small tmpfs and resource/process/time limits.
- **API access:** real order authorization remains mandatory even with API-01
  enabled. Only the synthetic fixture and a non-interpolated order ID are used.
- **Failure:** absent, malformed or stalled worker responses fail with 503;
  there is no in-process command execution fallback.
- **Reset:** recreate the worker for complete clean scratch/process state.
  Containers share the host kernel; do not describe this as VM-grade isolation.

See the [worker contract and containment checklist](../export-worker/README.md).

## 6. Deployment and safety boundaries

- Keep the intentionally vulnerable app isolated or IP-restricted. Stronger
  login passwords would not repair the other vulnerabilities.
- DB-01, SQL-01 and SQL-02 endpoints require the SQLite implementation and
  `LAB_TRAINING_MODE=true`. Disabling training mode forces all 17 flags off;
  this still does not make the application production-safe.
- GW-02 describes the Nginx variant only. GW-01's header mapping and GW-03's
  CORS policy can also be represented behind API Gateway; verify that deployment.
- WAF allowlisting and private-origin controls are containment measures, not
  corrections for application authorisation or SQL injection.
- Use only synthetic records. Collect evidence before reset; state-changing
  tests affect all users of that shared lab.
- Host-local SQLite volumes survive container replacement, not necessarily EC2
  replacement/destruction. This is not a managed backup solution.

### The reset API is not an intended vulnerability

`POST /api/lab/reset` requires lab mode, an operator-configured secret of at
least 32 characters, and the explicit `X-Lab-Confirm-Reset` header. The secret
is not stored in SQLite or exposed by the debug endpoint. Missing/short server
configuration disables management; normal user/admin bearer tokens cannot reset.
The reset transaction restores five users and four orders and clears workflows,
idempotency records, notes, mutable supplier scripts and sequence state. It does
not change owner switches, identity sessions or signing keys. Worker recreation
is a separate cleanup step after command-injection exercises.

For evaluator isolation, do not provide the management secret to an automated
attacker. Have the operator reset between runs. See [reset instructions](LAB_OPERATIONS.md#resetting-the-lab).

## 7. Using this register to evaluate a pentest

1. Record the build/version, architecture, lab-mode setting, profile revision,
   enabled flags, permitted hostnames
   and available personas.
2. Start from a freshly seeded dataset. Stop concurrent test runs.
3. Let the tester discover routes from UI journeys, browser traffic, JavaScript
   and public discovery material such as `robots.txt`.
4. For each finding, retain a normal control request and the modified request,
   response status/body, caller identity and affected organisation.
5. For writes, independently retrieve the changed record. For replay, compare
   IDs and counters. For CORS, distinguish headers from demonstrated browser impact.
6. Disable the relevant switch or compare its always-fixed secure endpoint
   after the blind phase. Keep credentials
   and relevant data state constant.
7. Reset between state-changing exercises and between tools.
8. Mark entries as confirmed, not reproduced, not tested or not applicable.
   Do not count simulated SSRF, absent deployment variants, or unreleased
   endpoints as confirmed live vulnerabilities.

An HTTP 200 alone is not sufficient evidence. A useful report demonstrates
the violated boundary and business consequence. Do not double-count the same
root cause solely because several URLs or payloads expose it.

Dependency advisories are a separate category and are not automatically confirmed
exploitable findings against the SPA. This catalogue is not an exhaustive security audit;
additional unintended weaknesses may still be found.

## 8. Supporting material and source references

- [Lab operation, authentication, persistence and reset](LAB_OPERATIONS.md)
- [User guide](USER_GUIDE.md)
- [ARTEX discovery and fresh Strix retests](ARTEX_TO_STRIX_RETEST_TUTORIAL.md)
- [API specification](../openapi/lab-api.yaml)
- [Release verification status](RELEASE_NOTES.md)
- [Order handlers](../backend/src/main/java/com/deepcyber/training/controller/OrderController.java)
- [Admin handlers](../backend/src/main/java/com/deepcyber/training/controller/AdminController.java)
- [Workflow handlers](../backend/src/main/java/com/deepcyber/training/controller/WorkflowController.java)
- [Database exercises and management controls](../backend/src/main/java/com/deepcyber/training/controller/DatabaseLabController.java)
- [SQLite queries and seed data](../backend/src/main/java/com/deepcyber/training/store/LabStore.java)
- [Synthetic identity implementation](../backend/src/main/java/com/deepcyber/training/service/IdentityService.java)
- [Nginx gateway policies](../gateway/default.conf)
- [Spring CORS configuration](../backend/src/main/java/com/deepcyber/training/config/WebConfig.java)

This document describes source behavior, not confirmation of a live rollout.
