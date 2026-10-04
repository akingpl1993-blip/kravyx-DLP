# ADR-003: Tenant isolation enforced in PostgreSQL with forced RLS
Status: accepted (2026-10-04)

Isolation in application code alone fails on the first missed `WHERE tenant_id`. Every
tenant table has FORCE ROW LEVEL SECURITY with `tenant_id = app.current_tenant()`; services
connect as `dlp_app` (not owner, NOBYPASSRLS) and set `app.tenant_id` per transaction from
the verified token. Unset context returns zero rows and rejects writes.

Consequences discovered while implementing:
- **Partitions do not inherit RLS policies.** Direct access to a partition bypasses the
  parent's policy (demonstrated in tests: 2 cross-tenant rows read without context). The
  runtime role has no privileges on partitions; `app.ensure_incident_partition` revokes on create.
- `tenants` is RLS-enabled but not FORCEd, so the SECURITY DEFINER path lookup does not
  recurse into its own policy. `dlp_app` is still subject to it.
- MSSPs see their descendant tenant rows but no descendant data rows; MSSP operations run
  under the child's tenant context after delegation checks (Phase 4).
