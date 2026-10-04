-- Simulates an attacker with owner/DBA access editing history. The chain must expose it.
\set A '00000000-0000-4000-8000-00000000000a'
BEGIN;
SELECT set_config('app.tenant_id', :'A', true);
ALTER TABLE dlp.audit_logs DISABLE TRIGGER audit_chain;
UPDATE dlp.audit_logs SET actor = 'someone.else' WHERE seq = 1;
DO $$ DECLARE broken bigint; BEGIN
  broken := app.verify_audit_chain(app.current_tenant());
  IF broken IS DISTINCT FROM 1 THEN RAISE EXCEPTION 'FAIL: tampering not detected (got %)', broken; END IF;
END $$;
ROLLBACK;
\echo 'tamper.sql: modification detected at seq 1'
