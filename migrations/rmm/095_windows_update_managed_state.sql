CREATE TABLE IF NOT EXISTS rmm_windows_update_management (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  inventory_id uuid NOT NULL REFERENCES rmm_device_inventory(id) ON DELETE CASCADE,
  agent_device_id uuid REFERENCES rmm_agent_devices(id) ON DELETE SET NULL,
  desired_managed boolean NOT NULL DEFAULT false,
  applied_managed boolean,
  policy_id uuid REFERENCES rmm_patch_policies(id) ON DELETE SET NULL,
  policy_name text NOT NULL DEFAULT '',
  agent_job_id uuid REFERENCES rmm_agent_jobs(id) ON DELETE SET NULL,
  last_result jsonb NOT NULL DEFAULT '{}'::jsonb,
  last_error text NOT NULL DEFAULT '',
  last_applied_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, inventory_id)
);

CREATE INDEX IF NOT EXISTS rmm_windows_update_management_policy_idx
  ON rmm_windows_update_management(tenant_id, policy_id, updated_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS rmm_windows_update_manage_active_job_uniq
  ON rmm_agent_jobs(tenant_id, agent_device_id)
  WHERE job_type='windows_update.manage'
    AND status IN ('queued','claimed')
    AND request_metadata->>'source'='windows_update_management';
