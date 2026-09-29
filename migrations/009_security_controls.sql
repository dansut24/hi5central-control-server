ALTER TABLE users
  ADD COLUMN IF NOT EXISTS password_changed_at timestamptz;

ALTER TABLE auth_sessions
  ADD COLUMN IF NOT EXISTS ip_address text,
  ADD COLUMN IF NOT EXISTS user_agent text,
  ADD COLUMN IF NOT EXISTS revoked_reason text;

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS password_reset_tokens_lookup_idx
  ON password_reset_tokens(token_hash, expires_at)
  WHERE used_at IS NULL;

CREATE INDEX IF NOT EXISTS password_reset_tokens_user_idx
  ON password_reset_tokens(tenant_id, user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS security_audit_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  session_id uuid REFERENCES auth_sessions(id) ON DELETE SET NULL,
  event_type text NOT NULL,
  outcome text NOT NULL DEFAULT 'success'
    CHECK (outcome IN ('success', 'failure', 'blocked')),
  ip_address text,
  user_agent text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS security_audit_events_tenant_created_idx
  ON security_audit_events(tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS security_audit_events_actor_idx
  ON security_audit_events(tenant_id, actor_user_id, created_at DESC);

CREATE OR REPLACE FUNCTION hi5_enforce_onboarding_mfa()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  require_mfa boolean;
BEGIN
  IF OLD.onboarding_step = 'security'
     AND NEW.onboarding_step IS DISTINCT FROM 'security' THEN
    require_mfa := COALESCE((NEW.onboarding_data -> 'security' ->> 'requireMfa')::boolean, false);

    IF require_mfa AND NOT EXISTS (
      SELECT 1
      FROM tenant_memberships m
      JOIN user_mfa_methods mm
        ON mm.tenant_id = m.tenant_id
       AND mm.user_id = m.user_id
       AND mm.method = 'totp'
       AND mm.enabled = true
       AND mm.verified_at IS NOT NULL
      WHERE m.tenant_id = NEW.tenant_id
        AND m.role IN ('owner', 'admin')
        AND m.status = 'active'
    ) THEN
      RAISE EXCEPTION 'Administrator MFA must be enrolled before onboarding can continue.'
        USING ERRCODE = 'P0001';
    END IF;
  END IF;

  IF NEW.onboarding_completed_at IS NOT NULL
     AND OLD.onboarding_completed_at IS NULL THEN
    require_mfa := COALESCE(
      (CASE
        WHEN NEW.configuration <> '{}'::jsonb
          THEN NEW.configuration -> 'security' ->> 'requireMfa'
        ELSE NEW.onboarding_data -> 'security' ->> 'requireMfa'
      END)::boolean,
      false
    );

    IF require_mfa AND NOT EXISTS (
      SELECT 1
      FROM tenant_memberships m
      JOIN user_mfa_methods mm
        ON mm.tenant_id = m.tenant_id
       AND mm.user_id = m.user_id
       AND mm.method = 'totp'
       AND mm.enabled = true
       AND mm.verified_at IS NOT NULL
      WHERE m.tenant_id = NEW.tenant_id
        AND m.role IN ('owner', 'admin')
        AND m.status = 'active'
    ) THEN
      RAISE EXCEPTION 'Administrator MFA must be enrolled before onboarding can be completed.'
        USING ERRCODE = 'P0001';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS tenant_settings_enforce_onboarding_mfa ON tenant_settings;
CREATE TRIGGER tenant_settings_enforce_onboarding_mfa
BEFORE UPDATE OF onboarding_step, onboarding_completed_at, onboarding_data, configuration
ON tenant_settings
FOR EACH ROW
EXECUTE FUNCTION hi5_enforce_onboarding_mfa();
