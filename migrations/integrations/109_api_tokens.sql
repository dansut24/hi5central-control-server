CREATE TABLE IF NOT EXISTS api_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name text NOT NULL,
  token_prefix text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  scopes text[] NOT NULL DEFAULT '{}'::text[],
  expires_at timestamptz,
  last_used_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (char_length(name) BETWEEN 2 AND 120),
  CHECK (cardinality(scopes) > 0)
);

CREATE INDEX IF NOT EXISTS api_tokens_tenant_user_idx
  ON api_tokens(tenant_id,user_id,created_at DESC);

CREATE INDEX IF NOT EXISTS api_tokens_active_idx
  ON api_tokens(token_hash)
  WHERE revoked_at IS NULL;
