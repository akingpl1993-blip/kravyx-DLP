\set A '00000000-0000-4000-8000-00000000000a'
\set B '00000000-0000-4000-8000-00000000000b'
\set M '00000000-0000-4000-8000-0000000000e0'

-- Helper: assert or raise.
CREATE TEMP TABLE results (name text, ok boolean);

-- ---- 0. The runtime role itself must not be able to bypass RLS.
DO $$ BEGIN
  IF (SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user) THEN
    RAISE EXCEPTION 'FAIL: dlp_app is superuser or BYPASSRLS';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE n.nspname='dlp' AND pg_get_userbyid(c.relowner)=current_user) THEN
    RAISE EXCEPTION 'FAIL: dlp_app owns a dlp table';
  END IF;
END $$;

-- ---- 1. Every tenant-owned table has RLS enabled + forced + a policy (guards future migrations).
DO $$ DECLARE r record; BEGIN
  FOR r IN SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
                  EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid) AS has_policy
           FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id'
           WHERE n.nspname = 'dlp' AND c.relkind IN ('r','p') AND NOT c.relispartition
  LOOP
    IF NOT (r.relrowsecurity AND r.relforcerowsecurity AND r.has_policy) THEN
      RAISE EXCEPTION 'FAIL: table dlp.% lacks forced RLS or a policy', r.relname;
    END IF;
  END LOOP;
END $$;

-- ---- 2. Partitions are not directly reachable (they do not inherit RLS).
DO $$ BEGIN
  PERFORM 1 FROM dlp.incidents_default LIMIT 1;
  RAISE EXCEPTION 'FAIL: dlp_app can read incidents_default directly';
EXCEPTION WHEN insufficient_privilege THEN NULL; END $$;

-- ---- 3. Seed data as each tenant.
BEGIN;
SELECT set_config('app.tenant_id', :'A', true);
INSERT INTO dlp.users (tenant_id, id, email, display_name, source) VALUES (:'A', gen_random_uuid(), 'a.user@a.example', 'A User', 'local');
INSERT INTO dlp.policies (tenant_id, id, name, created_by) VALUES (:'A', '10000000-0000-4000-8000-00000000000a', 'A policy', gen_random_uuid());
INSERT INTO dlp.incidents (tenant_id, id, number, channel, severity, action, dedup_key) VALUES (:'A', gen_random_uuid(), 1, 'usb_write', 'high', 'block', 'k-a');
INSERT INTO dlp.audit_logs (tenant_id, actor, action, object_type, result, prev_hash, hash) VALUES (:'A', 'a.user', 'policy.create', 'policy', 'success', '', '');
INSERT INTO dlp.audit_logs (tenant_id, actor, action, object_type, result, prev_hash, hash) VALUES (:'A', 'a.user', 'policy.publish', 'policy', 'success', '', '');
COMMIT;
BEGIN;
SELECT set_config('app.tenant_id', :'B', true);
INSERT INTO dlp.users (tenant_id, id, email, display_name, source) VALUES (:'B', gen_random_uuid(), 'b.user@b.example', 'B User', 'local');
INSERT INTO dlp.policies (tenant_id, id, name, created_by) VALUES (:'B', '10000000-0000-4000-8000-00000000000b', 'B policy', gen_random_uuid());
INSERT INTO dlp.incidents (tenant_id, id, number, channel, severity, action, dedup_key) VALUES (:'B', gen_random_uuid(), 1, 'web_upload', 'critical', 'block', 'k-b');
INSERT INTO dlp.audit_logs (tenant_id, actor, action, object_type, result, prev_hash, hash) VALUES (:'B', 'b.user', 'login', 'session', 'success', '', '');
COMMIT;

-- ---- 4. Tenant A sees only A, everywhere.
BEGIN;
SELECT set_config('app.tenant_id', :'A', true);
DO $$ DECLARE t text; n bigint; BEGIN
  FOREACH t IN ARRAY ARRAY['users','policies','incidents','audit_logs'] LOOP
    EXECUTE format('SELECT count(*) FROM dlp.%I WHERE tenant_id <> app.current_tenant()', t) INTO n;
    IF n <> 0 THEN RAISE EXCEPTION 'FAIL: tenant A sees % foreign rows in %', n, t; END IF;
    EXECUTE format('SELECT count(*) FROM dlp.%I', t) INTO n;
    IF n = 0 THEN RAISE EXCEPTION 'FAIL: tenant A sees none of its own rows in %', t; END IF;
  END LOOP;
END $$;
-- Guessing B's primary key returns nothing (IDOR).
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM dlp.policies WHERE id = '10000000-0000-4000-8000-00000000000b') THEN
    RAISE EXCEPTION 'FAIL: IDOR on policies';
  END IF;
END $$;
COMMIT;

-- ---- 5. Writes into another tenant are rejected (WITH CHECK).
BEGIN;
SELECT set_config('app.tenant_id', :'A', true);
DO $$ BEGIN
  INSERT INTO dlp.users (tenant_id, id, email, display_name, source)
  VALUES ('00000000-0000-4000-8000-00000000000b', gen_random_uuid(), 'x@b.example', 'X', 'local');
  RAISE EXCEPTION 'FAIL: cross-tenant insert succeeded';
EXCEPTION WHEN insufficient_privilege THEN NULL; END $$;
DO $$ BEGIN
  UPDATE dlp.policies SET tenant_id = '00000000-0000-4000-8000-00000000000b' WHERE tenant_id = app.current_tenant();
  RAISE EXCEPTION 'FAIL: moving a row to another tenant succeeded';
EXCEPTION WHEN insufficient_privilege THEN NULL; END $$;
-- Updating/deleting B's rows silently affects zero rows.
DO $$ DECLARE n int; BEGIN
  UPDATE dlp.policies SET name = 'pwned' WHERE id = '10000000-0000-4000-8000-00000000000b';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 0 THEN RAISE EXCEPTION 'FAIL: updated a foreign row'; END IF;
END $$;
COMMIT;

-- ---- 6. No tenant context => nothing visible, nothing writable.
BEGIN;
SELECT set_config('app.tenant_id', '', true);
DO $$ DECLARE n bigint; BEGIN
  SELECT (SELECT count(*) FROM dlp.users) + (SELECT count(*) FROM dlp.incidents) + (SELECT count(*) FROM dlp.tenants) INTO n;
  IF n <> 0 THEN RAISE EXCEPTION 'FAIL: % rows visible without tenant context', n; END IF;
END $$;
DO $$ BEGIN
  INSERT INTO dlp.users (tenant_id, id, email, display_name, source)
  VALUES ('00000000-0000-4000-8000-00000000000a', gen_random_uuid(), 'y@a.example', 'Y', 'local');
  RAISE EXCEPTION 'FAIL: insert without tenant context succeeded';
EXCEPTION WHEN insufficient_privilege THEN NULL; END $$;
COMMIT;

-- ---- 7. MSSP M lists its customer tree but cannot read customers' data rows.
BEGIN;
SELECT set_config('app.tenant_id', :'M', true);
DO $$ DECLARE names text; BEGIN
  SELECT string_agg(name, ',' ORDER BY name) INTO names FROM dlp.tenants;
  IF names <> 'A Finance,Customer A,MSSP M' THEN RAISE EXCEPTION 'FAIL: MSSP tenant view is %', names; END IF;
  IF EXISTS (SELECT 1 FROM dlp.incidents) THEN RAISE EXCEPTION 'FAIL: MSSP context reads customer incidents'; END IF;
END $$;
COMMIT;
BEGIN;
SELECT set_config('app.tenant_id', :'A', true);
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM dlp.tenants WHERE kind IN ('mssp','platform')) THEN
    RAISE EXCEPTION 'FAIL: customer can see its MSSP/platform ancestors';
  END IF;
END $$;
COMMIT;

-- ---- 8. Audit log: chained, append-only for the app.
BEGIN;
SELECT set_config('app.tenant_id', :'A', true);
DO $$ BEGIN
  IF (SELECT max(seq) FROM dlp.audit_logs) <> 2 THEN RAISE EXCEPTION 'FAIL: audit seq not per-tenant'; END IF;
  IF app.verify_audit_chain(app.current_tenant()) IS NOT NULL THEN RAISE EXCEPTION 'FAIL: fresh chain does not verify'; END IF;
END $$;
DO $$ BEGIN
  UPDATE dlp.audit_logs SET result = 'failure';
  RAISE EXCEPTION 'FAIL: app can update audit log';
EXCEPTION WHEN insufficient_privilege THEN NULL; END $$;
DO $$ BEGIN
  DELETE FROM dlp.audit_logs;
  RAISE EXCEPTION 'FAIL: app can delete audit log';
EXCEPTION WHEN insufficient_privilege THEN NULL; END $$;
COMMIT;

-- ---- 9. Policy versions are immutable; four-eyes enforced.
BEGIN;
SELECT set_config('app.tenant_id', :'A', true);
INSERT INTO dlp.policy_versions (tenant_id, id, policy_id, version, document, compiled_hash, created_by)
VALUES (:'A', '20000000-0000-4000-8000-00000000000a', '10000000-0000-4000-8000-00000000000a', 1, '{"rules":[]}', repeat('a', 64), '30000000-0000-4000-8000-000000000001');
UPDATE dlp.policy_versions SET approved_by = '30000000-0000-4000-8000-000000000002', published_at = now() WHERE id = '20000000-0000-4000-8000-00000000000a';
DO $$ BEGIN
  UPDATE dlp.policy_versions SET document = '{"rules":["evil"]}' WHERE id = '20000000-0000-4000-8000-00000000000a';
  RAISE EXCEPTION 'FAIL: published policy document was modified';
EXCEPTION WHEN insufficient_privilege THEN NULL; END $$;
DO $$ BEGIN
  INSERT INTO dlp.policy_versions (tenant_id, id, policy_id, version, document, compiled_hash, created_by, approved_by)
  VALUES (app.current_tenant(), gen_random_uuid(), '10000000-0000-4000-8000-00000000000a', 2, '{}', repeat('b', 64),
          '30000000-0000-4000-8000-000000000001', '30000000-0000-4000-8000-000000000001');
  RAISE EXCEPTION 'FAIL: self-approval accepted';
EXCEPTION WHEN check_violation THEN NULL; END $$;
COMMIT;

-- ---- 10. App cannot create tenants or grant itself licences.
DO $$ BEGIN
  INSERT INTO dlp.tenants (id, kind, name, path, region) VALUES (gen_random_uuid(), 'customer', 'Rogue', '/rogue/', 'ae');
  RAISE EXCEPTION 'FAIL: app created a tenant';
EXCEPTION WHEN insufficient_privilege THEN NULL; END $$;

\echo 'isolation.sql: all assertions passed'
