# ADR-002: Rust for shared inspection and policy engines
Status: accepted (2026-10-04)

Content inspection parses hostile input on every endpoint and server. Rust gives memory
safety without a runtime, and one library compiles into the agent, gateways (via C ABI
for Go) and cloud services, so a detector behaves identically everywhere.
Both crates are `#![forbid(unsafe_code)]`. The regex engine is linear-time, so tenant-
supplied patterns cannot cause catastrophic backtracking (tested).
