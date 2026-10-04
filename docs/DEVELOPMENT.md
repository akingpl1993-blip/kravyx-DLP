# Development

## Rust
Rust 1.80 (pinned in `rust-toolchain.toml`). Dependencies are pinned where newer
releases need a newer compiler (`time =0.3.36`). `cargo test --workspace --locked`.

## Database isolation suite
Needs a PostgreSQL 16 server you can reach as a superuser once, to create roles:

```sql
CREATE ROLE dlp_owner LOGIN NOSUPERUSER;            -- owns schema, runs migrations
CREATE ROLE dlp_app   LOGIN NOSUPERUSER NOBYPASSRLS; -- runtime services
CREATE DATABASE dlp OWNER dlp_owner;
```

Then `PGHOST=... make test-db`. The suite resets the schema, runs up/down/up,
seeds a platform → MSSP → customer → BU tree, and asserts isolation as `dlp_app`.
It was mutation-tested: granting partition access, un-forcing RLS on a table, or
giving `dlp_app` BYPASSRLS each make it fail.
