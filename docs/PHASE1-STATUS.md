# Phase 1 status

Phase 1 exit (gate G3, end of week 12): a USB copy on Windows of a file containing
Luhn-valid test cards is blocked; the incident and audit trail are visible in the console.

## Increment 1 — done (verified locally on Rust 1.80, PostgreSQL 16)

| Item | Evidence |
| --- | --- |
| inspect-core: NFKC + invisible-char normalisation, 12 detectors (cards, IBAN, AWS key/secret, private keys, JWT, GitHub tokens, DB URLs, email, Emirates ID, Aadhaar, PAN), Luhn/IIN/mod-97/Verhoeff/JWT validators, entropy, proximity, confidence, masking, budgets | 23 tests + 39 pack vectors; zero-width and full-width evasion defeated; clean business memo has no Medium/High findings; pathological regex completes < 2 s |
| policy-core: bundle compiler with precise errors, all/any/not, 13 operators, classification ranks, named lists, scope, channels, schedules, monitor mode, exceptions, most-restrictive-wins, one-incident-per-event, full explanation trace | 17 tests incl. both examples from the brief; fast and full modes agree |
| dlpctl simulator CLI | 12-card synthetic file → BLOCK with explanation; raw numbers absent from output (CI-enforced) |
| Schema: tenants/MSSP tree, licences, users, groups, RBAC with permission catalogue, devices, agents, classifications, policies, immutable policy versions with four-eyes check, partitioned incidents, evidence refs, hash-chained audit | migrations up/down/up as non-superuser |
| Isolation suite | 10 assertion groups as `dlp_app`; mutation-tested (3 mutations caught) |
| JSON Schemas (policy bundle, event envelope) | fixtures validate; misspelt field rejected |
| CI | fmt, clippy, tests, pack self-test, leak check, cargo-audit, schema checks, isolation on Postgres service, gitleaks, semgrep |

Not run locally: `clippy`, `cargo-audit`, gitleaks, semgrep (tools unavailable offline here); they run in CI.

## Remaining Phase 1 increments

| Increment | Scope |
| --- | --- |
| 1b | Go service foundation (config fail-closed, problem+json, security headers, telemetry); Policy Service API with C-ABI binding to policy-core; `POST /api/v1/policies/simulate` |
| 1c | Identity: OIDC for console, Entra ID/Okta federation, RBAC enforcement middleware, audit writer |
| 1d | Ingestion (gRPC, mTLS) → Kafka → Incident Service with dedup; OpenSearch indexing |
| 1e | Console: login, incidents queue + detail (masked evidence), policy list/builder v1, simulator UI, agents list |
| 1f | Windows agent (user mode): enrolment, mTLS, signed bundle cache, USB write interception via user-mode path, event buffering |
| 1g | Load and isolation hardening; G3 demo |

## Open decisions needing input
1. Product name and Go module / org path (placeholder: working name, `example.com/dlp`).
2. Build identity in-house vs Keycloak, and whether to reuse the PAM platform's identity/tenancy modules.
3. Start Microsoft (EV cert, Hardware Dev Center, MVI) and Apple (Endpoint Security entitlement) applications now; lead time is outside our control.
