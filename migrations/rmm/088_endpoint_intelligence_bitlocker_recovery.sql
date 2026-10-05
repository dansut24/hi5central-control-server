CREATE TABLE IF NOT EXISTS rmm_bitlocker_recovery_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  agent_device_id uuid NOT NULL REFERENCES rmm_agent_devices(id) ON DELETE CASCADE,
  inventory_id uuid REFERENCES rmm_device_inventory(id) ON DELETE SET NULL,
  drive text NOT NULL,
  protector_id text NOT NULL,
  protector_type text NOT NULL DEFAULT 'RecoveryPassword',
  recovery_password_encrypted text NOT NULL,
  recovery_password_hash text NOT NULL,
  source text NOT NULL DEFAULT 'agent_escrow',
  first_escrowed_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  last_revealed_at timestamptz,
  reveal_count integer NOT NULL DEFAULT 0,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, agent_device_id, protector_id)
);

CREATE INDEX IF NOT EXISTS idx_rmm_bitlocker_recovery_device
  ON rmm_bitlocker_recovery_keys (tenant_id, agent_device_id, revoked_at, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_rmm_bitlocker_recovery_hash
  ON rmm_bitlocker_recovery_keys (tenant_id, recovery_password_hash);

UPDATE access_roles
SET permissions = array_append(permissions, 'rmm.security.recovery_keys.read'),
    updated_at = now()
WHERE system_key = 'rmm-operator'
  AND active = true
  AND NOT ('rmm.security.recovery_keys.read' = ANY(permissions));
