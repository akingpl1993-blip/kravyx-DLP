#!/usr/bin/env bash
# Tenant-isolation and audit-integrity suite against a real PostgreSQL 16.
# Usage: PGHOST=... PGPORT=... tests/isolation/run.sh
# Requires roles: dlp_owner (owns schema, runs migrations) and dlp_app (runtime,
# NOSUPERUSER NOBYPASSRLS), and database `dlp` owned by dlp_owner.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$here/../.."
owner=(psql -X -q -v ON_ERROR_STOP=1 -U dlp_owner -d dlp)
app=(psql -X -q -v ON_ERROR_STOP=1 -U dlp_app -d dlp)

echo "== reset";        "${owner[@]}" -f "$root/migrations/000001_baseline.down.sql"
echo "== migrate up";   "${owner[@]}" -f "$root/migrations/000001_baseline.up.sql"
echo "== migrate down"; "${owner[@]}" -f "$root/migrations/000001_baseline.down.sql"
echo "== migrate up";   "${owner[@]}" -f "$root/migrations/000001_baseline.up.sql"
echo "== seed tenants (owner)"; "${owner[@]}" -f "$here/seed.sql"
echo "== isolation (dlp_app)";  "${app[@]}" -f "$here/isolation.sql"
echo "== tamper detection (owner)"; "${owner[@]}" -f "$here/tamper.sql"
echo "ALL ISOLATION TESTS PASSED"
