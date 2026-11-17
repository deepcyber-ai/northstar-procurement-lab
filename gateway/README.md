# Training gateway

This Nginx reverse proxy is intentionally vulnerable. It is safe only as part of
the isolated Deep Cyber sample lab and must never be placed in front of real users,
data, credentials, or cloud privileges.

The owner-controlled Vulnerable profile enables the seeded gateway lessons;
Fixed disables them. Runtime authorization and CORS decisions live in Spring
so switches take effect without rewriting/reloading Nginx. Fixed is not a
production-security guarantee. See [runtime controls](../docs/LAB_OPERATIONS.md#owner-controls).

It listens on port `8080` and exposes:

- `/` to the `frontend:80` container.
- `/api/*` to `backend:8080`, preserving the complete request URI.
- `/auth/*` and `/.well-known/*` to the identity endpoints, without API CORS.
- `/_gateway/health` as a local health check.

## Deliberate findings

### GW-01: browser headers become trusted identity

The browser sends `X-Training-User`, `X-Training-Tenant`, and
`X-Training-Role`. The gateway copies them into authoritative-looking
`X-Authenticated-*` headers and adds `X-Gateway-Verified: true`. Any HTTP client
can forge all of these values. The values are not secrets and are not signed.

Expected lesson: services must use a validated token or a cryptographically
bound identity from a trusted edge, and the edge must discard rather than trust
identity headers received from clients.

### GW-02: exact-path policy misses the subtree

Nginx overwrites `X-Lab-Gateway: nginx`; Spring models the gateway policy on
marked requests. The exact `/api/admin` route requires a real authenticated
administrator. With GW-02 on, `/api/admin/overview` misses that subtree check;
GW-01 separately controls whether its handler trusts an asserted role. Disable
GW-02 to apply the real-role check to the full administrative subtree. Neither
flag bypasses bearer authentication. This local lesson is not applied on AWS.

Expected lesson: authorization policies need normalized, prefix-aware route
matching and equivalent handling across HTTP methods. Backends must still
authorize every operation.

### GW-03: reflected credentialed CORS

With GW-03 on, non-secure API routes reflect the request's `Origin` and permit credentials. A
browser can therefore expose responses to an arbitrary origin when credentials
are present.

The backend's runtime CORS filter handles both actual requests and preflights;
Nginx does not append an independent CORS policy. Disabling GW-03 uses the
configured origin allowlist without credentials. `/api/secure/*` always uses
that fixed policy. The same filter is also used behind AWS API Gateway.

Expected lesson: allow only known origins, avoid credentialed CORS unless it is
necessary, and test preflight and actual responses together.

## Containment

The proxy has only two fixed upstreams (`frontend` and `backend`), a 1 MB request
body limit, and no cloud credentials or dynamic destination parameter. Keep the
Docker network private, publish only port `8080` to loopback where possible, and
destroy/reset the lab after each exercise.
