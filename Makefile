.PHONY: help build test test-rust test-db selftest fmt fmt-check simulate-demo ci

help:            ## list targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/'

build:           ## release build of dlpctl
	cargo build --release -p dlpctl

test: test-rust selftest test-db  ## everything

test-rust:       ## Rust unit + integration tests
	cargo test --workspace --locked

selftest: build  ## detector pack self-test + bundle validation
	./target/release/dlpctl detectors >/dev/null
	./target/release/dlpctl validate tests/fixtures/bundle-example.json

test-db:         ## tenant-isolation + audit-integrity suite (needs PGHOST and roles, see docs/DEVELOPMENT.md)
	tests/isolation/run.sh

fmt:             ## format Rust
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

simulate-demo: build  ## end-to-end: inspect a synthetic file and simulate a policy decision
	-./target/release/dlpctl simulate tests/fixtures/bundle-example.json tests/fixtures/context-genai.json tests/corpus/positive/card-export-12.csv

ci: fmt-check test
