# ADR-001: Monorepo
Status: accepted (2026-10-04)

The inspection and policy engines, protobuf/JSON contracts and detector packs must stay in
lockstep across agent, gateways and services. One repository with CODEOWNERS per path.
Kernel drivers live here but build in a separate restricted pipeline (EV signing).
