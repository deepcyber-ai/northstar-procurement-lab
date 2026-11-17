# NS-AUTHZ-001 — Cross-organisation order read

Status: REPLACE_WITH_CONFIRMED_AND_EVIDENCE_REFERENCE
Target origin: use only the approved origin in START_HERE.md.
Case version: REPLACE_CASE_VERSION

This is a known-finding retest template. Do not give it to a blind discovery
agent. Complete it from actual ARTEX/operator evidence, not from seeded answers.

## Original observation

Observation date / deployment / profile: REPLACE_DISCOVERY_CONTEXT
Ordinary order-detail request: REPLACE_OBSERVED_METHOD_AND_PATH_TEMPLATE
Alice-owned order ID and provenance: REPLACE_ALICE_ORDER_ID_AND_EVIDENCE
Bob-owned order ID and provenance: REPLACE_BOB_ORDER_ID_AND_EVIDENCE
Verified Alice role / tenant: REPLACE_ALICE_IDENTITY_BASELINE
Verified Bob role / tenant: REPLACE_BOB_IDENTITY_BASELINE
Redacted original baseline and cross-user evidence: REPLACE_EVIDENCE_PATHS
Relevant response fields proving the foreign record: REPLACE_RECORD_FIELDS
Exact request construction, preserving meaningful headers: REPLACE_REPRODUCTION

## Security requirement

A standard user must not obtain another organisation's order. Legitimate users
must retain access to their own orders. A filtered list or hidden UI control is
not proof that the detail endpoint enforces this requirement.

## Retest procedure

1. Obtain fresh normal OAuth sessions in separate clean Alice/Bob contexts.
2. Verify each identity and its current organisation/role through the observed
   application identity response. Stop on an unexpected identity or role.
3. Read Alice's selected order with Alice's access token; require a successful
   own-record response. Record relevant business fields.
4. Read Bob's selected order with Bob's access token; require the expected own
   record and record its ID/owner/tenant and relevant business fields.
5. Using Alice's same valid access token, send the original ordinary detail
   request for Bob's selected order once. Preserve the original method, route
   and meaningful headers; change only the deliberate object/identity variable.
   Do not substitute the paired /api/secure route or an administrator identity.
6. Recheck both legitimate own-order reads immediately afterward. Confirm that
   relevant business data was not changed by the case.
7. Stop and write the evidence, request ledger and verdict.

## Decision rules

- Still vulnerable: valid own-user baselines succeed and Alice receives Bob's
  actual foreign order. HTTP 200 alone without the record is insufficient.
- Fixed: valid baselines and post-checks succeed; the original cross-user
  reproduction is rejected with the reviewed denial behaviour and no foreign
  record, with no unintended business mutation.
- Inconclusive: failed/expired/revoked authentication, wrong role, missing or
  changed fixture, unexpected denial shape, network/gateway failure or insufficient
  evidence. A 401 or a failed legitimate baseline is not proof of a fix.
- Not executed: the case was never attempted; state why.

Reviewed expected denial for this deployment: REPLACE_EXPECTED_DENIAL
Allowed cleanup: normal own-session sign-out if appropriate; no business reset,
profile changes, volume deletion or interference with other users' sessions.
