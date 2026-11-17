# Northstar Procurement frontend

Northstar is an Angular 22 standalone purchasing workspace for an isolated security
assessment lab. It uses seeded identities and synthetic data. The default lab mode
is **Vulnerable**; owner-controlled switches select individual defects or the
**Fixed** comparison (all exercise switches off). Fixed mode is not a production
security certification.

## Features

- OAuth/OIDC sign-in through Northstar Login, with authorization code + S256 PKCE.
- Order list and direct order-detail routes.
- Persistent formatted purchasing notes, supplier delivery widget and purchase-order export.
- Workflow start and status refresh using `POST /api/workflows` and
  `GET /api/workflows/:id`.
- An admin navigation item that is hidden for non-admin users.
- A responsive, dependency-light UI served by Nginx in production.

Application API requests use the same-origin `/api` prefix. A container gateway
routes them to Spring locally; the AWS-native topology uses CloudFront and API
Gateway. The supplier JavaScript is a lab-owned resource, not a real vendor SDK.

## Deliberate client-side weakness

The application stores OAuth tokens in tab-scoped sessionStorage and
constructs `X-Training-User`, `X-Training-Tenant`, and `X-Training-Role` headers
in JavaScript. It also hides the admin link without guarding the `/admin` route.
These browser controls are forgeable. The corresponding backend exercises can
trust the role claim in Vulnerable mode; Fixed mode relies on verified server-side
identity and authorization. Hiding a link is never an authorization boundary.

Tokens are real lab credentials, not inert strings. Keep captures private.
Browser-readable tokens can be stolen by XSS. See [authentication and browser state](../docs/LAB_OPERATIONS.md#authentication-and-browser-state)
for token validation, refresh rotation, logout and the switchable PKCE exercise.

## Switchable browser exercises

| Exercise | Vulnerable | Fixed comparison |
| --- | --- | --- |
| XSS-01: stored purchasing notes | `bypassSecurityTrustHtml()` deliberately trusts stored user-authored HTML before `[innerHTML]`. | The same persisted HTML is passed as a plain string to Angular's normal HTML sanitizer. |
| SC-01: supplier integration | Any authenticated purchaser can overwrite the lab-owned widget; the page loads it without integrity checking. | Publishing is disabled and the browser requires an immutable, build-time SHA-384 SRI pin. |
| CMD-01: export format | The isolated worker interprets the format as shell input. | The backend and worker accept only `csv` or `json`, and the worker avoids a shell. |

Notes always require order-read/order-edit authorization, regardless of XSS-01 or
the order-detail BOLA flag. The fixed notes API returns the same raw data: the
rendering sink, not the storage endpoint, supplies the XSS correction. Export
output is always escaped text, never trusted HTML.

The fixed widget pin is defined in `src/app/core/ui-policy.service.ts` and matches
the immutable `SupplierWidget.TRUSTED_SCRIPT` backend constant. Never derive the
pin from the mutable widget response. When an existing widget has been tampered
with, Fixed mode blocks it and displays an unavailable message; an owner data reset
restores the original script. `/api/secure/vendor/widget.js` also serves the
immutable version for direct comparison.

### Runtime policy and previously opened tabs

`GET /api/ui-policy` is authenticated and read-only. It exposes only the two browser
flags, policy revision and immutable widget integrity. It does not expose owner
credentials or permit configuration changes. The client starts fixed and loads
no supplier script until a valid response arrives. Missing, invalid or unavailable
policy fails fixed.

The client polls every five seconds and reloads a page that previously rendered
unsafe content when policy changes or becomes unavailable. This is a best-effort
UX safeguard, **not containment of code that has already executed**: hostile
JavaScript could interfere with polling or persist browser state. Before trusting
a Fixed-mode comparison, close previously vulnerable tabs, clear lab-site data
or use a new private browser context, and sign in again. Owner controls remain on
a different origin and are not embedded in this application.

Stored notes and modified widget bytes survive application restarts. The protected
synthetic-data reset removes both. Switching Fixed on does not silently delete
test evidence or rewrite stored notes.

## Local development

```bash
npm ci
npm start
```

The development server alone does not provide same-origin identity/API routing.
For the integrated lab, build and run the project through the root Compose
configuration, then browse to `http://localhost:8080` through the gateway.

## Production build

```bash
npm run build
```

The Dockerfile builds with a supported Node 22 runtime and serves the resulting
SPA from Nginx. Direct client-side routes fall back to `index.html`.

## Browser regression checks

After a production build, use an existing Playwright installation and Chromium
browser to run the local-only fixture harness:

```bash
npm run build
PLAYWRIGHT_MODULE=/absolute/path/to/playwright/index.mjs \
BROWSER_EXECUTABLE=/absolute/path/to/chromium \
node scripts/test_content_browser.mjs
```

If Playwright and its browser are already discoverable, the environment variables
can be omitted. The harness never installs packages or browsers. It binds a random
localhost port, creates synthetic OIDC/JWKS fixtures and exercises the actual
built Angular UI. It checks harmless XSS/script markers, fixed sanitization, SRI
rejection, live policy changes, policy failure, note editing and escaped export
output. Backend authorization and persistence are covered separately by
`ContentLabTests` and `ContentPersistenceTests`. These checks do not demonstrate
that a live AWS deployment has been updated.
