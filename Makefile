.PHONY: help build ffi test test-rust test-go test-db selftest fmt fmt-check simulate-demo run-policy ci

help:            ## list targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/'

build:           ## release build of kravyxctl
	cargo build --release -p kravyxctl

test: test-rust test-go selftest test-db  ## everything

test-rust:       ## Rust unit + integration tests
	cargo test --workspace --locked

ffi:             ## build the Rust engine static library for Go
	cargo build --release -p kravyx-ffi

test-go: ffi     ## Go vet + race tests (needs the FFI library)
	go vet ./...
	go test -race -count=1 ./...

run-policy: ffi  ## run kravyx-policy locally (dev profile, random token printed once)
	@T=$$(openssl rand -hex 32); echo "dev token: $$T"; \
	KRAVYX_PROFILE=dev KRAVYX_DEV_TOKEN=$$T KRAVYX_DEV_TENANT_ID=00000000-0000-4000-8000-000000000001 \
	KRAVYX_DEV_PERMISSIONS=policy.read,policy.write go run ./services/policy/cmd/kravyx-policy

selftest: build  ## detector pack self-test + bundle validation
	./target/release/kravyxctl detectors >/dev/null
	./target/release/kravyxctl validate tests/fixtures/bundle-example.json

test-db:         ## tenant-isolation + audit-integrity suite (needs PGHOST and roles, see docs/DEVELOPMENT.md)
	tests/isolation/run.sh

fmt:             ## format Rust and Go
	cargo fmt --all
	gofmt -w .

fmt-check:
	cargo fmt --all -- --check
	test -z "$$(gofmt -l .)"

simulate-demo: build  ## end-to-end: inspect a synthetic file and simulate a policy decision
	-./target/release/kravyxctl simulate tests/fixtures/bundle-example.json tests/fixtures/context-genai.json tests/corpus/positive/card-export-12.csv

ci: fmt-check test
