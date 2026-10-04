# Kravyx DLP

Enterprise Data Loss Prevention: endpoint, web, network, email and cloud DLP with
discovery, classification, EDM/IDM fingerprinting, OCR, explainable risk, and
multi-tenant MSSP operation — deployable as SaaS, private SaaS, on-premises or hybrid.

Architecture: see the Phase 0 architecture document (items A–P) and `docs/adr/`.

**Status: Phase 1 — increments 1a (engines, tenancy) and 1b (Go platform, Policy Service API) done.**
What exists and what does not is tracked honestly in [docs/PHASE1-STATUS.md](docs/PHASE1-STATUS.md).

## Quick start

Requirements: Rust 1.80, Go 1.23 with cgo, PostgreSQL 16 client tools (isolation suite), Python 3 + `jsonschema`.

```bash
make test-rust        # 40 tests: detectors, validators, evasion, policy semantics
make selftest         # detector pack self-test (39 vectors) + bundle validation
make simulate-demo    # inspect a synthetic card file and simulate a policy decision
make test-db          # tenant isolation + audit tamper detection (see docs/DEVELOPMENT.md)
make test-go          # Go platform + Policy API (race detector)
make run-policy       # Policy Service on 127.0.0.1:8081, dev profile
```

`kravyxctl` is the simulator engine as a CLI:

```bash
./target/release/kravyxctl inspect   <file>
./target/release/kravyxctl validate  <bundle.json>
./target/release/kravyxctl simulate  <bundle.json> <context.json> [<file>]   # exit 3 = blocked
```

## Repository map

| Path | Contents | State |
| --- | --- | --- |
| `core/inspect-core` | Normalisation, data-driven detectors, validators, masking, budgets | Built, tested |
| `core/policy-core` | Policy bundle compiler + deterministic evaluator + explanation trace | Built, tested |
| `core/kravyxctl` | CLI: inspect, validate, simulate | Built |
| `core/ffi` | C ABI over the engines for Go (`include/kravyx.h`) | Built, tested |
| `internal/platform` | Go config, secrets, HTTP stack, metrics, auth | Built, tested |
| `services/policy` | Policy Service: validate + simulate API | Built, tested |
| `packages/openapi` | OpenAPI 3.1 contracts | Policy Service done |
| `migrations/` | PostgreSQL schema with forced RLS, MSSP tree, immutable policy versions, hash-chained audit | Built, tested |
| `packages/schemas/` | JSON Schemas: policy bundle, event envelope | Built, validated |
| `tests/isolation/` | Tenant-isolation and audit-integrity suite (mutation-tested) | Built |
| `tests/corpus/` | Synthetic DLP corpus (no real data) | Started |
| `apps/console/`, `agents/`, `gateways/`, `tools/indexer/`, `deploy/` | See each README | Not started |

## Security

Read [SECURITY.md](SECURITY.md). Never commit real personal data; the corpus is synthetic by rule.
