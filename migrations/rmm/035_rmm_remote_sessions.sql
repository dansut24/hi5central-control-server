CREATE TABLE IF NOT EXISTS rmm_remote_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  agent_device_id uuid NOT NULL REFERENCES rmm_agent_devices(id) ON DELETE CASCADE,
  inventory_id uuid NOT NULL REFERENCES rmm_device_inventory(id) ON DELETE CASCADE,
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  mode text NOT NULL DEFAULT 'console' CHECK (mode IN ('console','backstage')),
  viewer_client text NOT NULL DEFAULT 'native' CHECK (viewer_client IN ('native','browser')),
  viewer_token_hash text NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'created' CHECK (status IN ('created','viewer_connected','active','ended','expired','failed')),
  expires_at timestamptz NOT NULL,
  viewer_connected_at timestamptz,
  started_at timestamptz,
  ended_at timestamptz,
  last_activity_at timestamptz,
  end_reason text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_rmm_remote_sessions_tenant_created
  ON rmm_remote_sessions (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_rmm_remote_sessions_agent_status
  ON rmm_remote_sessions (agent_device_id, status, expires_at);
