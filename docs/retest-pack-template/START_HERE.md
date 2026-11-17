# Northstar reviewed retest pack

Approval: DRAFT
Pack revision: REPLACE_PACK_REVISION
Reviewed by / review date: REPLACE_REVIEWER_AND_DATE
Discovery evidence reference: REPLACE_DISCOVERY_EVIDENCE_REFERENCE

This template is not evidence of an executed test. The operator must complete
the placeholders, review the evidence and change Approval to APPROVED before use.
The separate interactive execution checkpoint still applies on every new run.

## Target and exclusions

Approved origin: http://localhost:8080
Deployment: local Docker lab

Only the exact approved origin and observed application/OAuth routes are in
scope. For local Docker, localhost ports 8081, 18080, 8787, 8788 and 48080,
ARTEX itself, Docker/host services, metadata, backend/owner networks and other
container addresses are excluded. Do not scan or reconfigure the relay.
Owner/demo/control/reset paths, other hosts, external/out-of-band callbacks,
uploads, arbitrary enumeration, brute force, denial of service and business
writes are excluded. Normal OAuth redirects to the approved-origin callback
are allowed for authentication.

Remote deployments are not authorised by this template. Use only this local
lab; do not treat another hostname or deployment as a fallback target.

## Cases and identities

Execute only briefs/NS-AUTHZ-001.md. That case is read-only for business data;
normal approved login/token exchange still creates authentication state.

Alice: REPLACE_ALICE_ACCOUNT_AND_VERIFIED_ORGANISATION
Bob: REPLACE_BOB_ACCOUNT_AND_VERIFIED_ORGANISATION
Authentication reference: synthetic accounts supplied in the INSTRUCTIONS.md prompt.

Use separate clean browser contexts and current credentials for each run.
Verify actual identity/role/tenant before testing. Do not use an administrator
or identity/role override headers. Never substitute Bob's token for Alice's
in the cross-user comparison; Bob's token is only for his legitimate baselines.
Northstar's SPA uses sessionStorage; do not assume a cookie/localStorage-only
export reproduces its authenticated state. Never use the ID token as an API token.

Provider keys, owner credentials and reset secrets must not appear in this pack.
Do not supply raw session exports as workspace files. Synthetic login credentials
in the startup prompt are visible to the selected model provider; use only the
approved lab accounts and data-handling path.

## Bounds and startup

Read INSTRUCTIONS.md, summarise the approved case, and wait for execution approval.
The operator configures and verifies connectivity; the tester does not change it.
Use sequential intentional API requests, normally at most one per second,
10-second request timeouts, and at most 20 intentional API requests for the case,
including identity/baseline/post-check calls. Record automatic browser/OAuth/asset
requests separately. Do not claim these prompt limits are hard network controls.

Stop on failed authentication, missing/mismatched fixtures, unexpected mutation,
rate limits, service impact or scope uncertainty. Do not reset the lab, switch
profiles, expand into other findings, or fill missing evidence by guessing.

## Required outputs

Create /workspace/retest-results/ with:

- report.md: pack revision, run ID, model, target, times, case verdict, evidence
  references, legitimate baseline results, observed profile behaviour and limits.
- retest-matrix.csv: one row per approved case, including the final verdict,
  explanation and evidence paths. No case may disappear from the report.
- tests.md: numbered ledger of intentional requests, UTC timestamps, principal,
  method/path, expected/observed result, status and evidence reference.
- evidence/: redacted baseline/test/post-check requests and responses; no tokens.

Use verdicts Fixed, Still vulnerable, Inconclusive or Not executed. Distinguish
the positive-control result from fix verification. Choose verdicts from executed
evidence, not the operator's desired profile. Report any unexecuted proposed
requests as Not executed. Note whether raw-traffic counts reconcile with the
ledger; if not, state that completeness is unverified against raw traffic.

Do not include raw session exports or credentials in the shareable outputs.
