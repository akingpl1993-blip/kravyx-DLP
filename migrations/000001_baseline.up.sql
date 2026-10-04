-- 000001 baseline: tenancy, identity/RBAC, devices/agents, classifications,
-- policies + immutable versions, incidents (partitioned), evidence refs,
-- and a hash-chained append-only audit log.
--
-- Isolation model (ADR-003):
--   * every tenant-owned table has tenant_id and FORCE ROW LEVEL SECURITY;
--   * the runtime role `dlp_app` is NOT the owner and has NOBYPASSRLS;
--   * services set `app.tenant_id` per transaction from the verified token;
--   * no tenant set => app.current_tenant() is NULL => zero rows, inserts fail.

CREATE SCHEMA IF NOT EXISTS dlp;
CREATE SCHEMA IF NOT EXISTS app;

CREATE OR REPLACE FUNCTION app.current_tenant() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT nullif(current_setting('app.tenant_id', true), '')::uuid
$$;

-- ---------------------------------------------------------------- tenants
CREATE TABLE dlp.tenants (
  id            uuid PRIMARY KEY,
  parent_id     uuid REFERENCES dlp.tenants(id),
  kind          text NOT NULL CHECK (kind IN ('platform','mssp','customer','business_unit')),
  name          text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  -- Materialised path of ids, '/'-separated, ending in '/': '/<root>/<mssp>/<customer>/'
  path          text NOT NULL UNIQUE,
  region        text NOT NULL,
  status        text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','offboarding')),
  kms_key_ref   text,
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- Path of the current tenant, read without RLS (SECURITY DEFINER, owner-only body).
CREATE OR REPLACE FUNCTION app.current_tenant_path() RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT path FROM dlp.tenants WHERE id = app.current_tenant()
$$;

ALTER TABLE dlp.tenants ENABLE ROW LEVEL SECURITY;
-- Not FORCEd: the owner must read tenants inside app.current_tenant_path() without
-- re-entering this policy (infinite recursion). dlp_app is never the owner, so RLS
-- still applies to every runtime query.
-- A tenant sees itself and its descendants (MSSP listing its customers).
-- It never sees siblings or ancestors. Data tables below are strictly own-tenant.
CREATE POLICY tenants_visible ON dlp.tenants FOR SELECT
  USING (path LIKE app.current_tenant_path() || '%');

CREATE TABLE dlp.licenses (
  tenant_id   uuid NOT NULL REFERENCES dlp.tenants(id),
  module      text NOT NULL CHECK (module IN ('core','endpoint','device_control','web','network','email','cloud','discovery','advanced_detection','genai','ueba','mssp')),
  seats       integer CHECK (seats IS NULL OR seats >= 0),
  valid_from  date NOT NULL,
  valid_to    date NOT NULL CHECK (valid_to >= valid_from),
  PRIMARY KEY (tenant_id, module)
);

-- ---------------------------------------------------------------- identity / RBAC
CREATE TABLE dlp.users (
  tenant_id     uuid NOT NULL REFERENCES dlp.tenants(id),
  id            uuid NOT NULL,
  external_id   text,
  email         text NOT NULL,
  display_name  text NOT NULL,
  source        text NOT NULL CHECK (source IN ('scim','ldap','local','sso_jit')),
  is_console_user boolean NOT NULL DEFAULT false,
  status        text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, email)
);

CREATE TABLE dlp.groups (
  tenant_id   uuid NOT NULL REFERENCES dlp.tenants(id),
  id          uuid NOT NULL,
  external_id text,
  name        text NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, name)
);

CREATE TABLE dlp.group_members (
  tenant_id uuid NOT NULL,
  group_id  uuid NOT NULL,
  user_id   uuid NOT NULL,
  PRIMARY KEY (tenant_id, group_id, user_id),
  FOREIGN KEY (tenant_id, group_id) REFERENCES dlp.groups(tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, user_id)  REFERENCES dlp.users(tenant_id, id)  ON DELETE CASCADE
);

-- Permissions are a global catalogue (not tenant data).
CREATE TABLE dlp.permissions (
  name        text PRIMARY KEY CHECK (name ~ '^[a-z_]+(\.[a-z_]+)+$'),
  description text NOT NULL,
  sensitive   boolean NOT NULL DEFAULT false
);

CREATE TABLE dlp.roles (
  tenant_id   uuid NOT NULL REFERENCES dlp.tenants(id),
  id          uuid NOT NULL,
  name        text NOT NULL,
  built_in    boolean NOT NULL DEFAULT false,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, name)
);

CREATE TABLE dlp.role_permissions (
  tenant_id  uuid NOT NULL,
  role_id    uuid NOT NULL,
  permission text NOT NULL REFERENCES dlp.permissions(name),
  PRIMARY KEY (tenant_id, role_id, permission),
  FOREIGN KEY (tenant_id, role_id) REFERENCES dlp.roles(tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE dlp.role_assignments (
  tenant_id   uuid NOT NULL,
  user_id     uuid NOT NULL,
  role_id     uuid NOT NULL,
  -- Optional narrowing to a descendant business unit.
  scope_tenant_id uuid REFERENCES dlp.tenants(id),
  granted_by  uuid,
  granted_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, user_id, role_id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES dlp.users(tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, role_id) REFERENCES dlp.roles(tenant_id, id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------- devices / agents
CREATE TABLE dlp.devices (
  tenant_id     uuid NOT NULL REFERENCES dlp.tenants(id),
  id            uuid NOT NULL,
  hostname      text NOT NULL,
  os            text NOT NULL CHECK (os IN ('windows','macos','linux')),
  os_version    text,
  serial        text,
  trust_level   text NOT NULL DEFAULT 'unknown' CHECK (trust_level IN ('unknown','unmanaged','managed','compliant')),
  owner_user_id uuid,
  last_seen_at  timestamptz,
  PRIMARY KEY (tenant_id, id)
);

CREATE TABLE dlp.agents (
  tenant_id       uuid NOT NULL,
  id              uuid NOT NULL,
  device_id       uuid NOT NULL,
  version         text NOT NULL,
  ring            text NOT NULL DEFAULT 'broad' CHECK (ring IN ('canary','pilot','broad')),
  cert_serial     text NOT NULL,
  cert_expires_at timestamptz NOT NULL,
  policy_version  text,
  health          text NOT NULL DEFAULT 'unknown' CHECK (health IN ('unknown','healthy','degraded','tampered','offline')),
  enrolled_at     timestamptz NOT NULL DEFAULT now(),
  revoked_at      timestamptz,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, cert_serial),
  FOREIGN KEY (tenant_id, device_id) REFERENCES dlp.devices(tenant_id, id)
);

-- ---------------------------------------------------------------- classification
CREATE TABLE dlp.classifications (
  tenant_id    uuid NOT NULL REFERENCES dlp.tenants(id),
  id           uuid NOT NULL,
  name         text NOT NULL,
  rank         smallint NOT NULL CHECK (rank >= 0),
  color        text CHECK (color ~ '^#[0-9a-fA-F]{6}$'),
  mip_label_id text,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, name),
  UNIQUE (tenant_id, rank)
);

-- ---------------------------------------------------------------- policies
CREATE TABLE dlp.policies (
  tenant_id          uuid NOT NULL REFERENCES dlp.tenants(id),
  id                 uuid NOT NULL,
  name               text NOT NULL,
  status             text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','in_review','approved','published','retired')),
  priority           integer NOT NULL DEFAULT 0,
  current_version_id uuid,
  created_by         uuid NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, name)
);

CREATE TABLE dlp.policy_versions (
  tenant_id      uuid NOT NULL,
  id             uuid NOT NULL,
  policy_id      uuid NOT NULL,
  version        integer NOT NULL CHECK (version >= 1),
  document       jsonb NOT NULL,
  compiled_hash  text NOT NULL CHECK (compiled_hash ~ '^[0-9a-f]{64}$'),
  signature      text,
  created_by     uuid NOT NULL,
  approved_by    uuid,
  published_at   timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, policy_id, version),
  -- Four-eyes: approver must differ from author.
  CHECK (approved_by IS NULL OR approved_by <> created_by),
  FOREIGN KEY (tenant_id, policy_id) REFERENCES dlp.policies(tenant_id, id)
);

CREATE OR REPLACE FUNCTION app.policy_versions_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  -- Only the approval/publication stamps may be set, once, on an existing version.
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'policy versions are immutable' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.document IS DISTINCT FROM OLD.document OR NEW.compiled_hash IS DISTINCT FROM OLD.compiled_hash
     OR NEW.version IS DISTINCT FROM OLD.version OR NEW.policy_id IS DISTINCT FROM OLD.policy_id
     OR NEW.created_by IS DISTINCT FROM OLD.created_by OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR (OLD.approved_by IS NOT NULL AND NEW.approved_by IS DISTINCT FROM OLD.approved_by)
     OR (OLD.published_at IS NOT NULL AND NEW.published_at IS DISTINCT FROM OLD.published_at)
     OR (OLD.signature IS NOT NULL AND NEW.signature IS DISTINCT FROM OLD.signature) THEN
    RAISE EXCEPTION 'policy versions are immutable' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER policy_versions_immutable BEFORE UPDATE OR DELETE ON dlp.policy_versions
  FOR EACH ROW EXECUTE FUNCTION app.policy_versions_immutable();

-- ---------------------------------------------------------------- incidents
CREATE TABLE dlp.incidents (
  tenant_id       uuid NOT NULL,
  id              uuid NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  number          bigint NOT NULL,
  user_id         uuid,
  device_id       uuid,
  channel         text NOT NULL,
  destination     jsonb NOT NULL DEFAULT '{}',
  policy_id       uuid,
  policy_version  text,
  rule_id         text,
  classification  text,
  detectors       jsonb NOT NULL DEFAULT '[]',   -- detector ids + counts + masked samples only
  file_name       text,
  file_sha256     text CHECK (file_sha256 IS NULL OR file_sha256 ~ '^[0-9a-f]{64}$'),
  severity        text NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  risk_score      smallint CHECK (risk_score BETWEEN 0 AND 100),
  risk_factors    jsonb NOT NULL DEFAULT '[]',
  action          text NOT NULL CHECK (action IN ('allow','audit','warn','justify','request_approval','encrypt','quarantine','block')),
  justification   text,
  status          text NOT NULL DEFAULT 'new' CHECK (status IN ('new','triaged','investigating','escalated','resolved','false_positive','closed')),
  assignee_id     uuid,
  sla_due_at      timestamptz,
  dedup_key       text NOT NULL,
  occurrences     integer NOT NULL DEFAULT 1 CHECK (occurrences >= 1),
  last_seen_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id, created_at)
) PARTITION BY RANGE (created_at);

CREATE TABLE dlp.incidents_default PARTITION OF dlp.incidents DEFAULT;
CREATE INDEX incidents_queue ON dlp.incidents (tenant_id, status, severity, created_at DESC);
CREATE INDEX incidents_dedup ON dlp.incidents (tenant_id, dedup_key, last_seen_at DESC);

CREATE OR REPLACE FUNCTION app.ensure_incident_partition(month date) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
  start date := date_trunc('month', month)::date;
  name  text := format('incidents_%s', to_char(start, 'YYYY_MM'));
BEGIN
  EXECUTE format('CREATE TABLE IF NOT EXISTS dlp.%I PARTITION OF dlp.incidents FOR VALUES FROM (%L) TO (%L)',
                 name, start, (start + interval '1 month')::date);
  -- Partitions do NOT inherit the parent's RLS policies. The runtime role must
  -- only ever reach incident rows through the parent table.
  EXECUTE format('REVOKE ALL ON dlp.%I FROM PUBLIC, dlp_app', name);
END $$;

CREATE TABLE dlp.incident_comments (
  tenant_id   uuid NOT NULL REFERENCES dlp.tenants(id),
  id          uuid NOT NULL,
  incident_id uuid NOT NULL,
  author_id   uuid NOT NULL,
  body        text NOT NULL CHECK (length(body) BETWEEN 1 AND 20000),
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);

CREATE TABLE dlp.evidence (
  tenant_id       uuid NOT NULL REFERENCES dlp.tenants(id),
  id              uuid NOT NULL,
  incident_id     uuid NOT NULL,
  kind            text NOT NULL CHECK (kind IN ('snippet','file','screenshot')),
  object_key      text NOT NULL,            -- encrypted object in tenant bucket/prefix
  sha256          text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  size_bytes      bigint NOT NULL CHECK (size_bytes >= 0),
  masked          boolean NOT NULL DEFAULT true,
  retention_until timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, id)
);

-- ---------------------------------------------------------------- audit log
CREATE TABLE dlp.audit_logs (
  tenant_id   uuid NOT NULL REFERENCES dlp.tenants(id),
  seq         bigint NOT NULL,
  ts          timestamptz NOT NULL DEFAULT clock_timestamp(),
  actor       text NOT NULL,
  source_ip   inet,
  action      text NOT NULL,
  object_type text NOT NULL,
  object_id   text,
  old_value   jsonb,
  new_value   jsonb,
  result      text NOT NULL CHECK (result IN ('success','failure','denied')),
  prev_hash   text NOT NULL,
  hash        text NOT NULL,
  PRIMARY KEY (tenant_id, seq)
);

CREATE OR REPLACE FUNCTION app.audit_row_digest(r dlp.audit_logs) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
  SELECT encode(sha256(convert_to(
    r.prev_hash || '|' || r.tenant_id || '|' || r.seq || '|' ||
    to_char(r.ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') || '|' ||
    r.actor || '|' || coalesce(host(r.source_ip), '') || '|' || r.action || '|' || r.object_type || '|' ||
    coalesce(r.object_id, '') || '|' || coalesce(r.old_value::text, '') || '|' ||
    coalesce(r.new_value::text, '') || '|' || r.result, 'UTF8')), 'hex')
$$;

-- Assigns seq and chains hash per tenant. Serialised per tenant with an advisory lock.
CREATE OR REPLACE FUNCTION app.audit_chain() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  last record;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('audit:' || NEW.tenant_id::text, 0));
  SELECT seq, hash INTO last FROM dlp.audit_logs WHERE tenant_id = NEW.tenant_id ORDER BY seq DESC LIMIT 1;
  NEW.seq       := coalesce(last.seq, 0) + 1;
  NEW.prev_hash := coalesce(last.hash, repeat('0', 64));
  NEW.ts        := clock_timestamp();
  NEW.hash      := app.audit_row_digest(NEW);
  RETURN NEW;
END $$;
CREATE TRIGGER audit_chain BEFORE INSERT ON dlp.audit_logs
  FOR EACH ROW EXECUTE FUNCTION app.audit_chain();

-- Returns the first seq whose hash or link does not verify, or NULL if intact.
CREATE OR REPLACE FUNCTION app.verify_audit_chain(t uuid) RETURNS bigint
LANGUAGE plpgsql STABLE AS $$
DECLARE
  r dlp.audit_logs;
  expected_prev text := repeat('0', 64);
  expected_seq bigint := 1;
BEGIN
  FOR r IN SELECT * FROM dlp.audit_logs WHERE tenant_id = t ORDER BY seq LOOP
    IF r.seq <> expected_seq OR r.prev_hash <> expected_prev OR r.hash <> app.audit_row_digest(r) THEN
      RETURN r.seq;
    END IF;
    expected_prev := r.hash;
    expected_seq := expected_seq + 1;
  END LOOP;
  RETURN NULL;
END $$;

-- ---------------------------------------------------------------- RLS on every tenant table
DO $$
DECLARE t text;
BEGIN
  FOR t IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
           WHERE n.nspname = 'dlp' AND c.relkind IN ('r','p') AND NOT c.relispartition
  LOOP
    EXECUTE format('ALTER TABLE dlp.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE dlp.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON dlp.%I USING (tenant_id = app.current_tenant()) WITH CHECK (tenant_id = app.current_tenant())', t);
  END LOOP;
END $$;

-- ---------------------------------------------------------------- grants
-- dlp_app: runtime role. Created by the installer (not here) as
--   CREATE ROLE dlp_app LOGIN NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA dlp, app TO dlp_app;
GRANT SELECT ON ALL TABLES IN SCHEMA dlp TO dlp_app;
GRANT INSERT, UPDATE, DELETE ON
  dlp.users, dlp.groups, dlp.group_members, dlp.roles, dlp.role_permissions, dlp.role_assignments,
  dlp.devices, dlp.agents, dlp.classifications, dlp.policies, dlp.incident_comments, dlp.evidence
  TO dlp_app;
GRANT INSERT, UPDATE ON dlp.incidents, dlp.policy_versions TO dlp_app;  -- no DELETE: retention job only
GRANT INSERT ON dlp.audit_logs TO dlp_app;                              -- append-only
-- Tenants and licences are provisioned by the Tenant service's separate role (Phase 1b).
REVOKE INSERT, UPDATE, DELETE ON dlp.tenants, dlp.licenses, dlp.permissions FROM dlp_app;
-- Partitions bypass parent RLS if queried directly: no direct access, ever.
REVOKE ALL ON dlp.incidents_default FROM PUBLIC, dlp_app;
GRANT EXECUTE ON FUNCTION app.current_tenant(), app.current_tenant_path(), app.verify_audit_chain(uuid) TO dlp_app;

-- ---------------------------------------------------------------- permission catalogue
INSERT INTO dlp.permissions (name, description, sensitive) VALUES
  ('incident.read',            'View incidents (masked)', false),
  ('incident.update',          'Triage, assign, comment, change status', false),
  ('incident.delete',          'Delete incidents', true),
  ('incident.evidence.view',   'View evidence (masked)', true),
  ('incident.evidence.unmask', 'View unmasked sensitive values', true),
  ('incident.evidence.download','Download evidence files', true),
  ('policy.read',              'View policies', false),
  ('policy.write',             'Create and edit draft policies', false),
  ('policy.approve',           'Approve policy versions', false),
  ('policy.publish',           'Publish and roll back policies', true),
  ('agent.read',               'View devices and agents', false),
  ('agent.manage',             'Issue agent commands, enrol, revoke', true),
  ('integration.manage',       'Configure integrations', true),
  ('user.manage',              'Manage users and role assignments', true),
  ('audit.read',               'View the audit log', false),
  ('report.read',              'View and export reports', false),
  ('tenant.manage',            'Manage tenant settings and child tenants', true);
