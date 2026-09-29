CREATE TABLE IF NOT EXISTS rmm_windows_update_controls (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  update_key text NOT NULL,
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','paused')),
  reason text NOT NULL DEFAULT '',
  paused_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  paused_at timestamptz,
  resumed_at timestamptz,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, update_key)
);

CREATE INDEX IF NOT EXISTS rmm_windows_update_controls_state_idx
  ON rmm_windows_update_controls(tenant_id, state, updated_at DESC);
