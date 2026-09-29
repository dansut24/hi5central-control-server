CREATE TABLE IF NOT EXISTS tenant_owner_transfer_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  current_owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  proposed_owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  requested_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  proposed_owner_email text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  approved_at timestamptz,
  cancelled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS tenant_owner_transfer_requests_tenant_idx
  ON tenant_owner_transfer_requests(tenant_id,created_at DESC);

CREATE TABLE IF NOT EXISTS platform_external_sync_state (
  sync_key text PRIMARY KEY,
  status text NOT NULL DEFAULT 'idle',
  started_at timestamptz,
  completed_at timestamptz,
  last_success_at timestamptz,
  last_error text NOT NULL DEFAULT '',
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO platform_external_sync_state (sync_key,status)
VALUES ('winget_repository','idle')
ON CONFLICT (sync_key) DO NOTHING;
