CREATE TABLE IF NOT EXISTS rmm_device_patch_rejections (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  agent_device_id uuid NOT NULL REFERENCES rmm_agent_devices(id) ON DELETE CASCADE,
  catalogue_id uuid NOT NULL REFERENCES rmm_software_catalogue(id) ON DELETE CASCADE,
  target_version text NOT NULL,
  reason text NOT NULL DEFAULT '',
  rejected_by_user_id uuid NULL REFERENCES users(id) ON DELETE SET NULL,
  rejected_by_label text NOT NULL DEFAULT 'Technician',
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz NULL,
  revoked_by_user_id uuid NULL REFERENCES users(id) ON DELETE SET NULL,
  UNIQUE (tenant_id, agent_device_id, catalogue_id, target_version)
);
CREATE INDEX IF NOT EXISTS idx_rmm_device_patch_rejections_active
  ON rmm_device_patch_rejections(tenant_id, agent_device_id, catalogue_id)
  WHERE revoked_at IS NULL;
