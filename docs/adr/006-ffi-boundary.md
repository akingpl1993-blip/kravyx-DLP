# ADR-006: Go services call the Rust engines through a C ABI
Status: accepted (2026-10-04)

Go services must evaluate policies exactly as agents and gateways do. Re-implementing
the evaluator in Go would let the two drift; a sidecar process would add a network hop
and a failure mode. `core/ffi` (crate `kravyx-ffi`) exposes `kx_policy_validate`,
`kx_policy_simulate`, `kx_engine_info` and `kx_free` as a static library linked via cgo.

Contract: JSON in, JSON out (`{"ok":true,"result":..}` / `{"ok":false,"error":{code,message}}`),
never NULL, caller frees with `kx_free`. Inputs over 8 MiB JSON / 10 MiB content are rejected
before reading. Go rejects NUL bytes before crossing (they would truncate silently).

Panics: every entry point runs under `catch_unwind`, so the workspace release profile
uses `panic = "unwind"` (changed from `abort`). A malformed input returns
`internal` instead of killing the Go process.

`kravyx-ffi` is the only crate permitted `unsafe`; `inspect-core` and `policy-core` remain
`#![forbid(unsafe_code)]`. Thread-safety is tested with 64 concurrent simulations under
the Go race detector.

Consequences: Go services need cgo and glibc (distroless/base, not static); the build
order is Rust static library first, then Go.
