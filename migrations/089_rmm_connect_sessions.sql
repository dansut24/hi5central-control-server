CREATE TABLE IF NOT EXISTS rmm_connect_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  support_code_hash text NOT NULL UNIQUE,
  support_code_hint text NOT NULL DEFAULT '',
  host_ticket_hash text UNIQUE,
  viewer_token_hash text UNIQUE,
  viewer_client text NOT NULL DEFAULT 'browser' CHECK (viewer_client IN ('browser','native')),
  status text NOT NULL DEFAULT 'waiting' CHECK (
    status IN ('waiting','claimed','host_connected','viewer_connected','active','ended','expired','failed')
  ),
  customer_consent_at timestamptz,
  claimed_at timestamptz,
  host_connected_at timestamptz,
  viewer_connected_at timestamptz,
  started_at timestamptz,
  ended_at timestamptz,
  expires_at timestamptz NOT NULL,
  last_activity_at timestamptz,
  end_reason text,
  host_name text NOT NULL DEFAULT '',
  host_platform text NOT NULL DEFAULT '',
  host_version text NOT NULL DEFAULT '',
  claim_attempt_count integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_rmm_connect_sessions_tenant_created
  ON rmm_connect_sessions (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_rmm_connect_sessions_status_expiry
  ON rmm_connect_sessions (status, expires_at);

CREATE INDEX IF NOT EXISTS idx_rmm_connect_sessions_host_ticket
  ON rmm_connect_sessions (host_ticket_hash)
  WHERE host_ticket_hash IS NOT NULL;
