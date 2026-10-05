CREATE TABLE IF NOT EXISTS portal_access_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  person_id uuid NOT NULL REFERENCES organisation_people(id) ON DELETE CASCADE,
  email text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (email = lower(email))
);

CREATE INDEX IF NOT EXISTS portal_access_tokens_lookup_idx
  ON portal_access_tokens(token_hash, expires_at)
  WHERE used_at IS NULL;

CREATE INDEX IF NOT EXISTS portal_access_tokens_person_idx
  ON portal_access_tokens(tenant_id, person_id, created_at DESC);
