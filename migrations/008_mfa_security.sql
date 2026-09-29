ALTER TABLE auth_sessions
  ADD COLUMN IF NOT EXISTS mfa_verified_at timestamptz;

CREATE TABLE IF NOT EXISTS user_mfa_methods (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  method text NOT NULL DEFAULT 'totp'
    CHECK (method IN ('totp')),
  secret_encrypted text NOT NULL,
  enabled boolean NOT NULL DEFAULT false,
  verified_at timestamptz,
  recovery_code_hashes jsonb NOT NULL DEFAULT '[]'::jsonb,
  last_used_step bigint,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, user_id, method)
);

CREATE INDEX IF NOT EXISTS user_mfa_methods_enabled_idx
  ON user_mfa_methods(tenant_id, user_id)
  WHERE enabled = true;

CREATE TABLE IF NOT EXISTS auth_mfa_challenges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  purpose text NOT NULL
    CHECK (purpose IN ('login', 'setup')),
  expires_at timestamptz NOT NULL,
  attempts integer NOT NULL DEFAULT 0,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS auth_mfa_challenges_lookup_idx
  ON auth_mfa_challenges(token_hash, expires_at)
  WHERE used_at IS NULL;

CREATE INDEX IF NOT EXISTS auth_mfa_challenges_user_idx
  ON auth_mfa_challenges(tenant_id, user_id, created_at DESC);
