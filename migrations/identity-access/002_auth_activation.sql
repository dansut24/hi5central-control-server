ALTER TABLE tenant_settings
  ADD COLUMN IF NOT EXISTS onboarding_data jsonb NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE user_email_verifications
  ADD COLUMN IF NOT EXISTS sent_at timestamptz,
  ADD COLUMN IF NOT EXISTS send_attempts integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS last_send_error text;

CREATE TABLE IF NOT EXISTS auth_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS auth_sessions_lookup_idx
  ON auth_sessions(token_hash, expires_at)
  WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS auth_sessions_user_idx
  ON auth_sessions(user_id, tenant_id);
