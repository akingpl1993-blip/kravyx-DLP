# DLP Platform (working name)

Enterprise Data Loss Prevention: endpoint, web, network, email and cloud DLP with
discovery, classification, EDM/IDM fingerprinting, OCR, explainable risk, and
multi-tenant MSSP operation — deployable as SaaS, private SaaS, on-premises or hybrid.

Architecture: see the Phase 0 architecture document (items A–P) and `docs/adr/`.

**Status: Phase 1, increment 1 — engines and tenancy foundation.**
What exists and what does not is tracked honestly in [docs/PHASE1-STATUS.md](docs/PHASE1-STATUS.md).

## Quick start

Requirements: Rust 1.80, PostgreSQL 16 client tools (for the isolation suite), Python 3 + `jsonschema` (schema checks).

```bash
make test-rust        # 40 tests: detectors, validators, evasion, policy semantics
make selftest         # detector pack self-test (39 vectors) + bundle validation
make simulate-demo    # inspect a synthetic card file and simulate a policy decision
make test-db          # tenant isolation + audit tamper detection (see docs/DEVELOPMENT.md)
```

`dlpctl` is the simulator engine as a CLI:

```bash
./target/release/dlpctl inspect   <file>
./target/release/dlpctl validate  <bundle.json>
./target/release/dlpctl simulate  <bundle.json> <context.json> [<file>]   # exit 3 = blocked
```

## Repository map

| Path | Contents | State |
| --- | --- | --- |
| `core/inspect-core` | Normalisation, data-driven detectors, validators, masking, budgets | Built, tested |
| `core/policy-core` | Policy bundle compiler + deterministic evaluator + explanation trace | Built, tested |
| `core/dlpctl` | CLI: inspect, validate, simulate | Built |
| `migrations/` | PostgreSQL schema with forced RLS, MSSP tree, immutable policy versions, hash-chained audit | Built, tested |
| `packages/schemas/` | JSON Schemas: policy bundle, event envelope | Built, validated |
| `tests/isolation/` | Tenant-isolation and audit-integrity suite (mutation-tested) | Built |
| `tests/corpus/` | Synthetic DLP corpus (no real data) | Started |
| `services/`, `apps/console/`, `agents/`, `gateways/`, `tools/indexer/`, `deploy/` | See each README | Not started |

## Security

Read [SECURITY.md](SECURITY.md). Never commit real personal data; the corpus is synthetic by rule.
